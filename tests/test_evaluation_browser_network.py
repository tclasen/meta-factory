"""Dormant devices never substitute for active, addressed or routed networks."""
import copy
import unittest
from unittest.mock import patch

from evaluation.browser_network import validate_network, verify_loopback_network


def snapshot():
    return dict(interfaces=[dict(index=1,name='lo',flags=73,ipv4_address='127.0.0.1'),
                            dict(index=2,name='dormant0',flags=128,ipv4_address=None)],
                ipv4_routes='Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n',
                ipv6_addresses='00000000000000000000000000000001 01 80 10 80 lo\n',
                ipv6_routes='0'*32+' 00 '+'0'*32+' 00 '+'0'*32+' ffffffff 00000001 00000000 00200200 lo\n')


class BrowserNetworkTest(unittest.TestCase):
    def test_stable_dormant_devices_and_loopback_only_pass(self):
        value=snapshot()
        with patch('evaluation.browser_network.collect_network',side_effect=[value,copy.deepcopy(value)]):
            verify_loopback_network()
        value['interfaces']=value['interfaces'][:1]
        self.assertTrue(validate_network(value))

    def test_active_or_addressed_interface_refused_regardless_of_name(self):
        for changes in ({'flags':129},{'flags':192},{'ipv4_address':'127.0.0.2'},
                        {'ipv4_address':'0.0.0.0'},{'name':'tunl0','flags':129}):
            value=snapshot();value['interfaces'][1].update(changes)
            with self.subTest(changes=changes),self.assertRaises(RuntimeError):validate_network(value)

    def test_nonloopback_routes_and_ipv6_addresses_refused(self):
        changes=[('ipv4_routes',snapshot()['ipv4_routes']+'dormant0 00000000 00000000 0000 0 0 0 00000000 0 0 0\n'),
                 ('ipv6_addresses','00000000000000000000000000000001 02 80 10 80 dormant0\n'),
                 ('ipv6_routes',snapshot()['ipv6_routes'].replace(' lo',' dormant0'))]
        for key,text in changes:
            value=snapshot();value[key]=text
            with self.subTest(key=key),self.assertRaises(RuntimeError):validate_network(value)

    def test_malformed_missing_duplicate_and_oversized_observations_refused(self):
        changes=[lambda v:v['interfaces'].append(dict(v['interfaces'][0])),
                 lambda v:v['interfaces'][1].update(index=True),
                 lambda v:v['interfaces'][1].update(flags=True),
                 lambda v:v['interfaces'][0].update(flags=1),
                 lambda v:v['interfaces'][0].update(ipv4_address='10.0.0.1'),
                 lambda v:v['interfaces'][0].update(ipv4_address=2130706433),
                 lambda v:v['interfaces'].pop(0),
                 lambda v:v.update(ipv4_routes=''),
                 lambda v:v.update(ipv4_routes='x'*65537),
                 lambda v:v.update(ipv6_addresses='bad'),
                 lambda v:v.update(ipv6_addresses=v['ipv6_addresses'].replace(' 01 ',' 02 ')),
                 lambda v:v.update(ipv6_routes='bad'),
                 lambda v:v.update(extra='unavailable')]
        for change in changes:
            value=snapshot();change(value)
            with self.assertRaises((RuntimeError,ValueError)):validate_network(value)

    def test_changed_configuration_refused_but_route_use_counters_ignored(self):
        first=snapshot();second=copy.deepcopy(first);second['interfaces'][1]['index']=3
        with patch('evaluation.browser_network.collect_network',side_effect=[first,second]),self.assertRaises(RuntimeError):
            verify_loopback_network()
        second=copy.deepcopy(first);second['ipv6_routes']=second['ipv6_routes'].replace('00000001 00000000','00000002 00000001')
        self.assertEqual(validate_network(first),validate_network(second))


if __name__=='__main__':unittest.main()
