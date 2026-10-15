#!/usr/bin/env python3
"""Real virtual-client tests of AWG, device bypass and emergency recovery.

Only the fixed lab namespace, source IP, route table, nft tables and service
units are changed. The household mode/config/service are never switched.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from gateway_safety import Gateway, atomic, command, load, runtime_hashes

NS = 'gw-ready-client'
HOST = 'gwtest-host'
PEER = 'gwtest-client'
BASE = Path('/run/home-gateway-lab')
DNS_DIR = Path('/etc/netns') / NS
FAILURE = Path('/run/systemd/system/home-gateway-lab.service.d/failure.conf')
AUTO_NS = 'gw-auto-test'
AUTO_HOST = 'gw-auto-host'
AUTO_AWG = 'gw-auto-awg'
AUTO_OVERRIDE = Path('/run/systemd/system/home-gateway-lab.service.d/netns.conf')


def wait_probe_listener(lab):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        result=command(['ip','netns','exec',AUTO_NS,'python3','-c',
                        "import socket; socket.create_connection(('127.0.0.1',"+str(lab.health_port)+"),timeout=0.3).close()"],check=False)
        if result.returncode==0:
            return
        time.sleep(0.1)
    raise RuntimeError('Auto-redirect test proxy did not become ready')


def auto_probe():
    script="import sys,json; sys.path.insert(0,'/usr/local/lib/home-gateway'); from gateway_safety import Gateway; print(json.dumps(Gateway(lab=True).probe()))"
    return json.loads(command(['ip','netns','exec',AUTO_NS,'python3','-c',script]).stdout)


def auto_redirect_test(lab, expected):
    """Run the complete engine and real virtual-client capture in a test netns.

    Dedicated eth0 and awg-home veth uplinks model the real gateway. Narrow
    root NAT/mark rules pass only these test sources to the physical/AWG paths.
    No custom mark is configured on the engine's working AWG outbound.
    """
    if ((Path('/run/netns') / AUTO_NS).exists() or AUTO_OVERRIDE.exists() or
            any(Path('/sys/class/net/'+name).exists() for name in (AUTO_HOST,AUTO_AWG))):
        raise RuntimeError('Auto-redirect lab resources already exist')
    for family,table in [('inet','home_gateway_lab_auto_guard'),('ip','home_gateway_lab_auto_nat')]:
        if command(['nft','list','table',family,table],check=False).returncode==0:
            raise RuntimeError('Auto-redirect lab table already exists')
    original = lab.build('rules')
    try:
        command(['systemctl','stop',lab.unit])
        command(['ip','netns','add',AUTO_NS])
        for root_name,peer_name,prefix in [(AUTO_HOST,'eth0','172.30.253'),(AUTO_AWG,'awg-home','172.30.252')]:
            temporary=root_name+'p'
            command(['ip','link','add',root_name,'type','veth','peer','name',temporary])
            command(['ip','link','set',temporary,'netns',AUTO_NS])
            command(['ip','-n',AUTO_NS,'link','set',temporary,'name',peer_name])
            command(['ip','address','add',prefix+'.1/30','dev',root_name])
            command(['ip','link','set',root_name,'mtu','1280','up'])
            command(['ip','-n',AUTO_NS,'address','add',prefix+'.2/30','dev',peer_name])
            command(['ip','-n',AUTO_NS,'link','set',peer_name,'mtu','1280','up'])
        command(['ip','-n',AUTO_NS,'link','set','lo','up'])
        command(['ip','-n',AUTO_NS,'route','add','default','via','172.30.253.1'])
        command(['ip','-n',AUTO_NS,'route','add','table','30477','default','via','172.30.252.1','dev','awg-home'])
        command(['ip','-n',AUTO_NS,'rule','add','priority','8101','oif','awg-home','table','30477'])
        command(['ip','netns','exec',AUTO_NS,'sysctl','-q','-w','net.ipv4.ip_forward=1'])
        # This is only the virtual client's link, never eth0 or another LAN device.
        command(['ip','link','set',HOST,'netns',AUTO_NS])
        command(['ip','-n',AUTO_NS,'address','replace','192.0.2.1/30','dev',HOST])
        command(['ip','-n',AUTO_NS,'link','set',HOST,'up'])
        root_rules='''table inet home_gateway_lab_auto_guard {
 chain awg_route { type filter hook prerouting priority -90; policy accept;
  iifname "gw-auto-awg" ip saddr 172.30.252.2 meta mark set 0x415747
 }
}
table ip home_gateway_lab_auto_nat {
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
  iifname "gw-auto-host" oifname "eth0" ip saddr 172.30.253.2 masquerade
  iifname "gw-auto-awg" oifname "awg-home" ip saddr 172.30.252.2 masquerade
 }
}
'''
        subprocess.run(['nft','-f','-'],input=root_rules,text=True,capture_output=True,check=True)
        config = copy.deepcopy(original)
        for outbound in config['outbounds']:
            outbound.pop('routing_mark',None)
        tun = next(row for row in config['inbounds'] if row['type']=='tun')
        tun.update(auto_route=True,auto_redirect=True,dns_mode='disabled',auto_redirect_nfqueue=101)
        AUTO_OVERRIDE.parent.mkdir(parents=True,exist_ok=True)
        AUTO_OVERRIDE.write_text('[Service]\nNetworkNamespacePath=/run/netns/'+AUTO_NS+'\n')
        command(['systemctl','daemon-reload'])
        atomic(lab.config,config,0o640,'sing-box')
        command(['systemctl','restart',lab.unit])
        wait_probe_listener(lab)
        guard_script="import sys,json; sys.path.insert(0,'/usr/local/lib/home-gateway'); from network_guard import apply; from pathlib import Path; apply(json.loads(Path('/run/home-gateway-lab/settings/network.json').read_text()),'rules')"
        command(['ip','netns','exec',AUTO_NS,'python3','-c',guard_script])
        if trace_ip(curl(['https://www.cloudflare.com/cdn-cgi/trace']))!=expected or not auto_probe():
            raise RuntimeError('Complete namespaced auto-redirect HTTPS/DNS did not use AWG')
        dns_test()
        dns_test(tcp=True)
        # Prove the prior bug is detected by this test topology.
        broken = copy.deepcopy(config)
        next(row for row in broken['outbounds'] if row['tag']=='vps')['routing_mark']=0x415747
        atomic(lab.config,broken,0o640,'sing-box')
        command(['systemctl','restart',lab.unit])
        wait_probe_listener(lab)
        if auto_probe():
            raise RuntimeError('Regression test did not reject the incompatible legacy mark')
        invocation=command(['systemctl','show',lab.unit,'-p','InvocationID','--value']).stdout.strip()
        logs=''
        for _ in range(10):
            logs=command(['journalctl','_SYSTEMD_INVOCATION_ID='+invocation,'-o','cat','--no-pager']).stdout
            if 'routing_mark` is conflict with `tun.auto_redirect' in logs:
                break
            time.sleep(0.1)
        if 'routing_mark` is conflict with `tun.auto_redirect' not in logs:
            raise RuntimeError('Legacy-mark failure was not the expected runtime conflict')
    except Exception:
        diagnostic={}
        for name,args in [
            ('namespace_rules',['ip','-n',AUTO_NS,'-4','rule','show']),
            ('namespace_routes',['ip','-n',AUTO_NS,'-4','route','show','table','all']),
            ('namespace_nft',['ip','netns','exec',AUTO_NS,'nft','list','ruleset']),
            ('root_forward_route',['ip','-4','route','get','1.1.1.1','from','172.30.252.2','iif',AUTO_AWG,'mark','0x415747']),
            ('engine_logs',['journalctl','-u',lab.unit,'--since','1 minute ago','-o','cat','--no-pager','-n','60'])]:
            r=command(args,check=False)
            diagnostic[name]={'returncode':r.returncode,'stdout':r.stdout[-14000:],'stderr':r.stderr[-1000:]}
        atomic(BASE/'auto-redirect-diagnostic.json',diagnostic)
        raise
    finally:
        command(['systemctl','stop',lab.unit],check=False)
        if AUTO_OVERRIDE.exists():
            AUTO_OVERRIDE.unlink()
            command(['systemctl','daemon-reload'])
        if command(['ip','-n',AUTO_NS,'link','show',HOST],check=False).returncode==0:
            command(['ip','-n',AUTO_NS,'link','set',HOST,'netns','1'])
            command(['ip','address','replace','192.0.2.1/30','dev',HOST])
            command(['ip','link','set',HOST,'up'])
        for family,table in [('inet','home_gateway_lab_auto_guard'),('ip','home_gateway_lab_auto_nat')]:
            command(['nft','delete','table',family,table],check=False)
        command(['ip','link','delete',AUTO_HOST],check=False)
        command(['ip','link','delete',AUTO_AWG],check=False)
        command(['ip','netns','delete',AUTO_NS],check=False)
        atomic(lab.config,original,0o640,'sing-box')
        command(['systemctl','start',lab.unit])
        tun_route()


def snapshot():
    return {'mode': Path('/etc/home-gateway/mode').read_text(),
            'config_sha256': hashlib.sha256(Path('/etc/sing-box/config.json').read_bytes()).hexdigest(),
            'main_pid': command(['systemctl','show','sing-box.service','-p','MainPID','--value']).stdout.strip(),
            'default': command(['ip','-j','-4','route','show','default']).stdout}


def curl(args, client=True):
    prefix = ['ip','netns','exec',NS] if client else []
    result=command(prefix + ['curl','--noproxy','*','-4','--silent','--show-error','--connect-timeout','4',
                             '--max-time','12','--max-filesize','65536'] + args, timeout=15,check=False)
    if result.returncode:
        raise RuntimeError('Virtual-client HTTPS request failed: '+result.stderr[:300])
    return result.stdout


def trace_ip(text):
    ip = next((line[3:] for line in text.splitlines() if line.startswith('ip=')), None)
    if not ip:
        raise RuntimeError('Trace returned no exit IP')
    return ip


def tun_route():
    for _ in range(30):
        if Path('/sys/class/net/gw-test-tun').exists():
            command(['ip','-4','route','replace','table','30478','default','dev','gw-test-tun'])
            return
        time.sleep(0.1)
    raise RuntimeError('Lab TUN did not appear')


def dns_test(tcp=False):
    args=['ip','netns','exec',NS,'dig','@192.0.2.1','example.com','A','+short','+time=3','+tries=1']
    if tcp:
        args.append('+tcp')
    result=command(args).stdout.strip()
    addresses=[line for line in result.splitlines() if line and line[0].isdigit()]
    if not addresses or any(line.startswith('198.18.') or line.startswith('198.19.') for line in addresses):
        raise RuntimeError('DNS did not return real IPv4 answers')


def cleanup():
    for unit in ('home-gateway-lab.service','home-gateway-lab-dns.service'):
        command(['systemctl','stop',unit],check=False)
        command(['systemctl','reset-failed',unit],check=False)
    if AUTO_OVERRIDE.exists():
        AUTO_OVERRIDE.unlink()
        command(['systemctl','daemon-reload'])
    if FAILURE.exists():
        FAILURE.unlink()
        command(['systemctl','daemon-reload'])
    command(['ip','-4','rule','del','priority','8200','from','192.0.2.2/32','table','30478'],check=False)
    command(['ip','-4','route','flush','table','30478'],check=False)
    command(['ip','link','delete',HOST],check=False)
    command(['ip','netns','delete',NS],check=False)
    for family,table in [('inet','home_gateway_lab_guard'),('ip','home_gateway_lab_nat')]:
        command(['nft','delete','table',family,table],check=False)
    if DNS_DIR.exists():
        shutil.rmtree(DNS_DIR)


def verify():
    if os.geteuid():
        raise RuntimeError('Run as root')
    original=snapshot()
    if original['mode'].strip()!='direct':
        raise RuntimeError('Preparation is permitted only while household mode is direct')
    if BASE.exists() and not (BASE/'owned').exists():
        raise RuntimeError('Unrecognized lab directory')
    if Path('/run/netns/'+NS).exists() or Path('/sys/class/net/'+HOST).exists() or DNS_DIR.exists() or FAILURE.exists():
        raise RuntimeError('Lab resources already exist; inspect them before retrying')
    if any(row.get('priority')==8200 for row in json.loads(command(['ip','-j','-4','rule','show']).stdout)):
        raise RuntimeError('Lab priority is already in use')
    BASE.mkdir(mode=0o750,exist_ok=True)
    shutil.chown(BASE,group='sing-box')
    (BASE/'owned').touch()
    settings=BASE/'settings'
    settings.mkdir(mode=0o700,exist_ok=True)
    data_dir=BASE/'data'
    data_dir.mkdir(mode=0o750,exist_ok=True)
    shutil.chown(data_dir,user='sing-box',group='sing-box')
    actual=Gateway()
    network=dict(actual.network,lan_ip='192.0.2.1',lan_cidr='192.0.2.0/30',
                 incoming_interface=HOST,nft_prefix='home_gateway_lab')
    policy=copy.deepcopy(actual.policy)
    policy['direct_client_ips']=[]
    for name,value in [('network.json',network),('policy.json',policy),
                       ('awg-outbound.json',load(actual.settings/'awg-outbound.json')),
                       ('safety.json',load(actual.settings/'safety.json'))]:
        atomic(settings/name,value)
    atomic(settings/'mode','direct\n')
    atomic(BASE/'fallback-dns.json',{'listen':'192.0.2.1','lan_cidr':'192.0.2.0/30',
                                   'upstream':network['upstream_dns']},0o640,'sing-box')
    tests={}
    try:
        command(['ip','netns','add',NS])
        DNS_DIR.mkdir(mode=0o755)
        (DNS_DIR/'resolv.conf').write_text('nameserver 192.0.2.1\n')
        command(['ip','link','add',HOST,'type','veth','peer','name',PEER])
        command(['ip','link','set',PEER,'netns',NS])
        command(['ip','address','add','192.0.2.1/30','dev',HOST])
        command(['ip','link','set',HOST,'up'])
        command(['ip','-n',NS,'address','add','192.0.2.2/30','dev',PEER])
        command(['ip','-n',NS,'link','set',PEER,'up'])
        command(['ip','-n',NS,'link','set','lo','up'])
        command(['ip','-n',NS,'route','add','default','via','192.0.2.1'])
        command(['ip','-4','rule','add','priority','8200','from','192.0.2.2/32','table','30478'])
        baseline_ip=trace_ip(curl(['--interface','eth0','https://www.cloudflare.com/cdn-cgi/trace'],client=False))
        lab=Gateway(lab=True)
        lab.rules(seconds=600)
        tun_route()
        expected=load(settings/'safety.json')['expected_exit_ip']
        if trace_ip(curl(['https://www.cloudflare.com/cdn-cgi/trace']))!=expected:
            raise RuntimeError('Virtual client did not exit through AWG')
        tests['awg_virtual_client_exit']=True
        dns_test()
        dns_test(tcp=True)
        tests['dns_udp_tcp_real_answers']=True
        if not lab.probe():
            raise RuntimeError('End-to-end safety probe failed')
        tests['local_safety_probe']=True
        # Exercise a Russian-service domain and an IP-only TCP flow through the real engine.
        curl(['--head','https://yandex.com/'])
        command(['ip','netns','exec',NS,'python3','-c',
                 "import socket; s=socket.create_connection(('77.88.55.60',443),timeout=5); s.close()"],timeout=8)
        invocation=command(['systemctl','show',lab.unit,'-p','InvocationID','--value']).stdout.strip()
        logs=command(['journalctl','_SYSTEMD_INVOCATION_ID='+invocation,'-o','cat','--no-pager']).stdout
        tests['russian_service_reachable']=True
        tests['geoip_direct_flow_logged']=any('outbound/direct[direct]' in line and '77.88.55.60:443' in line for line in logs.splitlines())
        if not tests['geoip_direct_flow_logged']:
            raise RuntimeError('No direct GeoIP TCP flow observed')
        auto_redirect_test(lab,expected)
        tests['auto_redirect_virtual_client_https_dns']=True
        tests['legacy_mark_conflict_regression']=True
        # One virtual gaming device must bypass even the normal foreign default.
        lab.policy['direct_client_ips']=['192.0.2.2']
        atomic(settings/'policy.json',lab.policy)
        # Direct clients bypass the userspace TUN entirely. Remove only this
        # lab client's test rule, never any household routing rule.
        command(['ip','-4','rule','del','priority','8200','from','192.0.2.2/32','table','30478'])
        lab.rules(seconds=600)
        tun_route()
        if trace_ip(curl(['https://www.cloudflare.com/cdn-cgi/trace']))!=baseline_ip:
            raise RuntimeError('Device bypass did not use direct egress')
        tests['gaming_device_direct_bypass']=True
        # Expire only the lab trial; exercise the exact production rollback code.
        activation=load(lab.activation_path)
        activation['deadline']=int(time.time())-1
        atomic(lab.activation_path,activation)
        lab.watch()
        if lab.mode_path.read_text().strip()!='direct':
            raise RuntimeError('Trial timeout did not roll back')
        if trace_ip(curl(['https://www.cloudflare.com/cdn-cgi/trace']))!=baseline_ip:
            raise RuntimeError('Direct connectivity was not restored after timeout')
        tests['confirmation_timeout_rollback']=True
        # Break only the lab outbound. The VPS and household engine remain running.
        lab.policy['direct_client_ips']=[]
        atomic(settings/'policy.json',lab.policy)
        command(['ip','-4','rule','add','priority','8200','from','192.0.2.2/32','table','30478'])
        lab.rules(seconds=600)
        tun_route()
        broken=lab.build('rules')
        next(row for row in broken['outbounds'] if row['tag']=='vps')['bind_interface']='awg-broken'
        atomic(lab.config,broken,0o640,'sing-box')
        command(['systemctl','restart',lab.unit],check=False)
        for _ in range(3):
            lab.watch()
        if lab.mode_path.read_text().strip()!='direct':
            raise RuntimeError('Three failures did not roll back')
        tests['three_failures_rollback']=True
        # A persistently crashing engine must still recover kernel forwarding and DNS.
        FAILURE.parent.mkdir(parents=True,exist_ok=True)
        FAILURE.write_text('[Service]\nExecStart=\nExecStart=/usr/bin/false\n')
        command(['systemctl','daemon-reload'])
        result=lab.direct('lab_main_process_failed',automatic=True)
        if not result['fallback_dns_active'] or not result['last_transition']['kernel_fallback']:
            raise RuntimeError('Standby DNS/kernel fallback not active')
        dns_test()
        dns_test(tcp=True)
        if trace_ip(curl(['https://www.cloudflare.com/cdn-cgi/trace']))!=baseline_ip:
            raise RuntimeError('Kernel fallback did not restore Internet')
        tests['crashed_engine_kernel_and_dns_recovery']=True
    finally:
        cleanup()
        if snapshot()!=original:
            raise RuntimeError('Household configuration, service PID or physical default changed')
    tests['household_unchanged']=True
    candidate=actual.build('rules')
    actual.validate(candidate)
    digest=hashlib.sha256(json.dumps(candidate,sort_keys=True).encode()).hexdigest()
    report={'schema_version':1,'ready':all(tests.values()),'verified_at':int(time.time()),
            'candidate_sha256':digest,'runtime_source_sha256':runtime_hashes(),'tests':tests,'household_mode':'direct',
            'switch_authorized':False,'scope':'real virtual client; household traffic was not activated'}
    atomic(actual.settings/'readiness.json',report)
    atomic('/var/lib/home-gateway-control/readiness-report.json',report,0o640,'vpn-monitor')
    print(json.dumps(report))
    return report


if __name__=='__main__':
    verify()
