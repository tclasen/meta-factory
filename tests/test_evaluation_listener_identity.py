"""Isolated proc-layout controls; native kernel identity needs separate sbx validation."""
import hashlib
import ipaddress
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.listener_identity_probe import IdentityIncomplete, observe, process_start, socket_rows


HEADER = 'sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n'


def row(host='0100007F', port=9000, inode=123):
    remote = '0' * len(host)
    return ('0: ' + host + ':' + format(port, '04X') + ' ' + remote + ':0000 '
            '0A 00000000:00000000 00:00000000 00000000 503 0 ' + str(inode) + ' 1\n')


class ListenerIdentityTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory();self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name).resolve();self.proc = self.root / 'proc'
        selected = self.proc / '42'
        for name in ('fd', 'net', 'ns'):(selected / name).mkdir(parents=True)
        (self.proc / 'self/ns').mkdir(parents=True)
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (selected / 'stat').write_text('42 (comm with ) space) S ' + '0 ' * 18 + '123\n')
        (selected / 'ns/net').write_bytes(b'namespace fixture')
        os.link(selected / 'ns/net', self.proc / 'self/ns/net')
        (selected / 'net/tcp').write_text(HEADER + row())
        (selected / 'net/tcp6').write_text(HEADER)
        (selected / 'fd/7').symlink_to('socket:[123]')
        (self.proc / 'sys/kernel/random/boot_id').write_text('owned fixture boot identity\n')
        self.binary = self.root / 'executable';self.binary.write_bytes(b'owned executable fixture')
        (selected / 'exe').symlink_to(self.binary)
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def observe(self, **changes):
        args = dict(pid=42, start_ticks='123', expected_sha256=self.digest, address='127.0.0.1', port=9000,
                    proc=self.proc, addresses=set())
        args.update(changes)
        return observe(**args)

    def test_selected_executable_listener_and_namespace_are_bound(self):
        result = self.observe()
        self.assertEqual(result['outcome'], 'listener_identity_observed')
        self.assertEqual(result['listener_rows'], [('127.0.0.1', 123, 503)])
        self.assertEqual(result['executable_sha256'], self.digest)
        self.assertTrue(result['same_network_namespace'])
        self.assertFalse(result['provider_semantics_verified'])
        self.assertFalse(result['response_route_verified'])
        self.assertFalse(result['runtime_memory_verified'])
        self.assertNotIn(str(self.binary), str(result))
        self.assertEqual(process_start(self.proc / '42', 42), '123')

    def test_wrong_start_hash_port_owner_and_shared_listener_are_inconclusive(self):
        for changes in ({'start_ticks':'124'}, {'expected_sha256':'0' * 64}, {'port':9001}):
            with self.subTest(changes=changes), self.assertRaises(IdentityIncomplete):self.observe(**changes)
        other = self.proc / '43/fd';other.mkdir(parents=True);(other / '8').symlink_to('socket:[123]')
        with self.assertRaises(IdentityIncomplete):self.observe()
        (self.proc / '42/fd/7').unlink()
        with self.assertRaises(IdentityIncomplete):self.observe()

    def test_wildcard_requires_matching_namespace_and_assigned_address(self):
        (self.proc / '42/net/tcp').write_text(HEADER + row(host='00000000'))
        self.assertEqual(self.observe()['outcome'], 'listener_identity_observed')
        with self.assertRaises(IdentityIncomplete):self.observe(address='10.42.0.5')
        self.assertEqual(self.observe(address='10.42.0.5', addresses={ipaddress.ip_address('10.42.0.5')})['outcome'],
                         'listener_identity_observed')
        (self.proc / 'self/ns/net').unlink();(self.proc / 'self/ns/net').write_bytes(b'other namespace')
        with self.assertRaises(IdentityIncomplete):self.observe()

    def test_ipv6_rows_and_cross_family_wildcard_are_distinguished(self):
        path = self.proc / '42/net/tcp6'
        path.write_text(HEADER + row(host='00000000000000000000000001000000'))
        self.assertEqual(str(socket_rows(path, 6)[0][0]), '::1')
        self.assertEqual(self.observe(address='::1')['outcome'], 'listener_identity_observed')
        path.write_text(HEADER + row(host='0' * 32))
        with self.assertRaises(IdentityIncomplete):self.observe()

    def test_executable_or_listener_change_during_read_and_deadline_are_inconclusive(self):
        original = os.fstat;changed = [False]
        def mutate(descriptor):
            info = original(descriptor)
            if info.st_ino == self.binary.stat().st_ino and not changed[0]:
                changed[0] = True;self.binary.write_bytes(b'owned executable fixture')
                os.utime(self.binary, ns=(info.st_atime_ns, info.st_mtime_ns))
            return info
        with patch('evaluation.listener_identity_probe.os.fstat', side_effect=mutate):
            with self.assertRaises(IdentityIncomplete):self.observe()
        with patch('evaluation.listener_identity_probe.time.monotonic', side_effect=[0, 36]):
            with self.assertRaises(IdentityIncomplete):self.observe()

    def test_public_and_metadata_addresses_are_refused_before_reads(self):
        for address in ('8.8.8.8', '169.254.169.254', '0.0.0.0', 'ff02::1'):
            with self.subTest(address=address), self.assertRaises(ValueError):self.observe(address=address)

    def test_unknown_owner_permissions_missing_fds_and_bad_tables_never_verify(self):
        with patch('evaluation.listener_identity_probe.os.scandir', side_effect=PermissionError('private')):
            with self.assertRaises(PermissionError):self.observe()
        (self.proc / '42/fd/7').unlink();(self.proc / '42/fd').rmdir()
        with self.assertRaises(IdentityIncomplete):self.observe()
        (self.proc / '42/fd').mkdir();(self.proc / '42/fd/7').symlink_to('socket:[123]')
        (self.proc / '42/net/tcp').write_text('unknown table\n')
        with self.assertRaises(IdentityIncomplete):self.observe()


if __name__ == '__main__':
    unittest.main()
