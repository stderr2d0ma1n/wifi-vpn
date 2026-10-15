#!/usr/bin/env python3
"""Alternate actual AWG/VLESS requests while preserving the home direct baseline."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import time
from zoneinfo import ZoneInfo

NAMESPACE = 'home-awg-test'
RUNTIME = '/usr/local/lib/home-awg/awg_runtime.py'


def invariant():
    subprocess.run(['python3', RUNTIME, 'verify-baseline'], check=True, capture_output=True)


def ticks():
    result = {}
    for name, unit in [('awg','home-awg-probe'), ('vless','home-vps-probe'), ('main','sing-box')]:
        pid = subprocess.check_output(['systemctl','show',unit,'--property=MainPID','--value'], text=True).strip()
        data = Path('/proc/' + pid + '/stat').read_text().rsplit(')',1)[1].split()
        result[name] = int(data[11]) + int(data[12])
    return result


def curl(route, url, expected_size=None, resolve=None):
    prefix = ['ip','netns','exec',NAMESPACE] if route == 'awg' else []
    proxy = 'socks5://127.0.0.1:18080' if route == 'vless' else ''
    command = prefix + ['curl','-4','-fLsS','--http1.1','--proxy',proxy,
        '--proto','=https','--proto-redir','=https','--connect-timeout','10','--max-time','60',
        '-o','/dev/null','-w','%{http_code} %{size_download} %{time_total} %{time_starttransfer}']
    if resolve:
        command += ['--resolve', resolve]
    before = ticks()
    started = time.monotonic()
    completed = subprocess.run(command + [url], capture_output=True, text=True)
    elapsed = time.monotonic() - started
    after = ticks()
    try:
        status,size,duration,ttfb=completed.stdout.strip().split()
        status,size,duration,ttfb=int(status),int(size),float(duration),float(ttfb)
    except ValueError:
        status,size,duration,ttfb=0,0,elapsed,elapsed
    success = completed.returncode == 0 and status == 200 and (expected_size is None or size == expected_size)
    return {'route':route,'success':success,'curl_exit':completed.returncode,'status':status,
        'bytes':size,'seconds':duration,'first_byte_seconds':ttfb,
        'mbps':size * 8 / duration / 1e6 if duration else 0,
        'cpu_one_core_percent':{k:round((after[k]-before[k])/os.sysconf('SC_CLK_TCK')/elapsed*100,1) for k in before},
        'temperature_c':int(Path('/sys/class/thermal/thermal_zone0/temp').read_text())/1000}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--rounds',type=int,default=4)
    parser.add_argument('--large-bytes',type=int,default=70590635)
    parser.add_argument('--large-url',default='https://go.dev/dl/go1.27.2.linux-amd64.tar.gz')
    parser.add_argument('--large-only',action='store_true')
    args=parser.parse_args()
    if os.geteuid()!=0 or not 2 <= args.rounds <= 10 or not 20000000 <= args.large_bytes <= 200000000:
        parser.error('Run as root with bounded test sizes')
    invariant()
    args.output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    os.close(fd)
    speed_ip=socket.getaddrinfo('speed.cloudflare.com',443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
    latency_ip=socket.getaddrinfo('www.cloudflare.com',443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
    assert ipaddress.ip_address(speed_ip).is_global and ipaddress.ip_address(latency_ip).is_global
    report={'started_moscow':datetime.datetime.now(ZoneInfo('Europe/Moscow')).isoformat(),
            'method':'Sequential alternating requests on one Orange Pi. Same pinned Cloudflare target IP per endpoint; HTTP/1.1, IPv4, fresh curl process. AWG userspace 3.1 in namespace versus VLESS REALITY loopback SOCKS; home stays direct.',
            'speed_ip':speed_ip,'latency_ip':latency_ip,'samples':[]}
    def sample(stage,route,url,size=None,resolve=None):
        row=dict(stage=stage,**curl(route,url,size,resolve))
        report['samples'].append(row)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(row),flush=True)
    latency_url='https://www.cloudflare.com/cdn-cgi/trace'
    latency_resolve='www.cloudflare.com:443:'+latency_ip
    speed_resolve='speed.cloudflare.com:443:'+speed_ip
    if not args.large_only:
        for _ in range(3):sample('latency','direct',latency_url,resolve=latency_resolve)
        for n in range(10):
            for route in (['awg','vless'] if n%2==0 else ['vless','awg']):
                sample('latency',route,latency_url,resolve=latency_resolve)
        medium_url='https://speed.cloudflare.com/__down?bytes=20000000'
        for _ in range(2):sample('medium','direct',medium_url,20000000,speed_resolve)
        for n in range(args.rounds):
            for route in (['awg','vless'] if n%2==0 else ['vless','awg']):
                sample('medium',route,medium_url,20000000,speed_resolve)
    for n in range(2):
        for route in (['awg','vless'] if n%2==0 else ['vless','awg']):
            sample('large',route,args.large_url,args.large_bytes)
    if not args.large_only:
        other_url='https://deb.sagernet.org/files/ver_Gz0vP/sing-box_1.14.3_linux_amd64.deb'
        for route in ['vless','awg']:
            sample('independent',route,other_url,32297878)
    invariant()
    summary={}
    for route in ['direct','vless','awg']:
        rows=[x for x in report['samples'] if x['route']==route]
        latency=[x['seconds']*1000 for x in rows if x['stage']=='latency' and x['success']]
        speeds=[x['mbps'] for x in rows if x['stage']=='medium' and x['success']]
        summary[route]={'successes':sum(x['success'] for x in rows),'total':len(rows),
            'latency_median_ms':statistics.median(latency) if latency else None,
            'latency_max_ms':max(latency) if latency else None,
            'medium_median_mbps':statistics.median(speeds) if speeds else None,
            'medium_min_mbps':min(speeds) if speeds else None,
            'medium_max_mbps':max(speeds) if speeds else None}
        summary[route]['large_mbps']=[x['mbps'] for x in rows if x['stage']=='large' and x['success']]
    report['summary']=summary
    report['finished_moscow']=datetime.datetime.now(ZoneInfo('Europe/Moscow')).isoformat()
    report['home_baseline_unchanged']=True
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'summary':summary,'home_baseline_unchanged':True}),flush=True)


if __name__=='__main__':
    main()
