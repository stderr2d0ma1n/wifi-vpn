import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from build_config import build
from gateway_safety import Gateway, decision
from network_guard import nft_script


class SafetyTests(unittest.TestCase):
    def test_expired_trial_and_reboot_always_roll_back(self):
        activation={'confirmed':False,'deadline':100,'boot_id':'same'}
        self.assertEqual(decision('rules',activation,True,100,'same')[0],'confirmation_timeout')
        self.assertEqual(decision('rules',activation,True,50,'different')[0],'confirmation_timeout')

    def test_three_failures_and_success_resets_counter(self):
        activation={'confirmed':True,'failures':0}
        for count in (1,2):
            result, failures=decision('rules',activation,False,0,'')
            self.assertEqual((result,failures),('observe',count))
            activation['failures']=failures
        self.assertEqual(decision('rules',activation,False,0,'')[0],'connectivity_failed')
        self.assertEqual(decision('rules',activation,True,0,''),('observe',0))
        self.assertEqual(decision('direct',activation,False,0,''),('idle',0))

    def test_domain_overrides_and_device_bypass_precede_country_data(self):
        policy={'direct_suffixes':['ru'],'vpn_domains':['example.ru'], 'direct_domains':['example.com'],
                'direct_client_ips':['10.0.0.157'], 'rule_sets':[
                    {'tag':'blocked','role':'vpn_domains','path':'/rules/blocked.srs'},
                    {'tag':'ru','role':'direct_ip','path':'/rules/ru.srs'}]}
        config=build('10.0.0.148','10.0.0.0/24','eth0','10.0.0.1',policy,'rules',
                     {'type':'direct','bind_interface':'awg-home','routing_mark':0x415747})
        rules=config['route']['rules']
        index=lambda key,value:next(i for i,row in enumerate(rules) if row.get(key)==value)
        self.assertLess(index('source_ip_cidr',['10.0.0.157/32']),index('domain_suffix',['example.ru']))
        self.assertLess(index('domain_suffix',['example.ru']),index('domain_suffix',['ru']))
        self.assertLess(index('rule_set',['blocked']),index('domain_suffix',['ru']))
        self.assertLess(index('domain_suffix',['example.com']),index('rule_set',['ru']))
        self.assertFalse(any(row.get('server')=='dns-fake' for row in config['dns']['rules']))
        self.assertEqual(config['outbounds'][1]['bind_interface'],'awg-home')
        self.assertNotIn('routing_mark',config['outbounds'][1])
        self.assertTrue(config['inbounds'][1]['auto_redirect'])
        self.assertEqual(config['route']['final'],'vps')

    def test_lab_guard_has_its_own_tables_and_ingress(self):
        network={'lan_ip':'192.0.2.1','lan_cidr':'192.0.2.0/30','interface':'eth0','upstream_dns':'10.0.0.1',
                 'incoming_interface':'gwtest-host','nft_prefix':'home_gateway_lab'}
        text=nft_script(network,'rules',set())
        self.assertIn('home_gateway_lab_guard',text)
        self.assertIn('iifname "gwtest-host" oifname "eth0"',text)
        self.assertNotIn('table inet home_gateway_guard',text)

    def test_gaming_client_bypasses_tun_and_is_allowed_by_forward_guard(self):
        network={'lan_ip':'10.0.0.148','lan_cidr':'10.0.0.0/24','interface':'eth0','upstream_dns':'10.0.0.1',
                 'direct_client_ips':['10.0.0.157']}
        rules=nft_script(network,'rules',set())
        self.assertIn('meta mark set 0x2024 ct mark set 0x2024',rules)
        self.assertLess(rules.index('counter accept'),rules.index('counter drop'))
        self.assertNotIn('device_bypass',nft_script(network,'direct',set()))

    def test_direct_policy_does_not_depend_on_rule_files_or_vps(self):
        policy={'rule_sets':[{'broken':'unused until rules mode'}]}
        config=build('10.0.0.148','10.0.0.0/24','eth0','10.0.0.1',policy,'direct')
        self.assertEqual(config['route']['final'],'direct')
        self.assertEqual(len(config['outbounds']),1)


if __name__=='__main__':
    unittest.main()
