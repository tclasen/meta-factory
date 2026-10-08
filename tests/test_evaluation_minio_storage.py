"""Provider composition controls; fixture observations do not establish application acceptance."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import patch

from evaluation.minio_storage_probe import PROFILE, main
from evaluation.storage_policy_semantics import classify_response
from evaluation.storage_route_probe import accepted_inodes, address
from evaluation.listener_identity_probe import read_bounded
from evaluation.minio_storage import capture_minio_storage
from evaluation.evidence import Attempt


class Response:
    def __init__(self, status, raw):self.status, self.raw = status, raw
    def __enter__(self):return self
    def __exit__(self, *args):pass
    def read(self, limit):return self.raw[:limit]


class MinioStorageTest(unittest.TestCase):
    def observe(self, *, classification='absent', changed=False, route_changed=False,
                provider_changed=False, cleanup=True, unknown=False):
        config = dict(endpoint='http://127.0.0.1:9000', bucket='fixture-bucket')
        counts = dict(policy=0, listener=0, route=0, canary=0)
        class Peer:
            def __init__(self, _):self.opener = self
            def check(self, *args):pass
            def open(self, *args, **kwargs):
                counts['policy'] += 1
                kind = 'public' if changed and counts['policy'] == 2 else classification
                if kind == 'absent':return Response(404, b'<Error><Code>NoSuchBucketPolicy</Code></Error>')
                entry = dict(Effect='Allow', Principal='*', Action='s3:GetObject', Resource='arn:aws:s3:::fixture-bucket/evidence/*')
                if kind == 'conditional':entry['Condition'] = {'Bool':{'aws:SecureTransport':'true'}}
                return Response(200, json.dumps(dict(Version='2012-10-17', Statement=[entry])).encode())
        def canary(_):
            counts['canary'] += 1
            return dict(outcome='pass' if cleanup else 'cleanup_incomplete', key='factory-evaluation-canary/' + 'a'*32,
                        versions=[], read_write_checked=True, anonymous_read_denied=True,
                        anonymous_write_denied=True, cleanup_verified=cleanup)
        def listener(*args):
            counts['listener'] += 1
            return dict(same_network_namespace=True, net_namespace_device=1,
                        net_namespace_inode=2 + int(provider_changed and counts['listener'] == 2))
        def route(*args):
            counts['route'] += 1
            return dict(pid=42, address='127.0.0.1', port=9000, net_namespace_device=1,
                        net_namespace_inode=2 + int(route_changed and counts['route'] == 2))
        signing = dict(private_binding=lambda _:config, urllib=urllib, datetime=datetime, timezone=timezone,
                       signed_headers=lambda *args:{}, Peer=Peer, observe=canary, ipaddress=ipaddress)
        output = io.StringIO()
        with patch.object(sys, 'argv', ['probe', '/private/binding', 'unknown' if unknown else PROFILE, '42', '123']):
            with redirect_stdout(output):main(signing, {'classify_response':classify_response}, {'observe':listener}, {'observe_route':route})
        return json.loads(output.getvalue()), counts

    def test_supported_absent_policy_composes_anonymous_denial_without_other_claims(self):
        result, counts = self.observe()
        self.assertEqual(result['outcome'], 'storage_provider_observed')
        self.assertTrue(result['private_anonymous_verified'])
        self.assertTrue(result['read_write_checked'])
        self.assertTrue(result['cleanup_verified'])
        self.assertFalse(result['abort_suite'])
        self.assertEqual(counts, dict(policy=2, listener=2, route=2, canary=1))
        for field in ('atomic_snapshot_verified', 'credential_exposure_verified', 'future_changes_verified'):
            self.assertFalse(result[field])

    def test_public_prefix_canary_pass_does_not_establish_whole_bucket_private(self):
        result, _ = self.observe(classification='public')
        self.assertEqual(result['canary_outcome'], 'pass')
        self.assertFalse(result['private_anonymous_verified'])
        self.assertTrue(result['abort_suite'])

    def test_conditional_policy_unknown_profile_and_changed_bindings_remain_inconclusive(self):
        for options in ({'classification':'conditional'}, {'changed':True}, {'route_changed':True},
                        {'provider_changed':True}, {'unknown':True}, {'cleanup':False}):
            with self.subTest(options=options):
                result, counts = self.observe(**options)
                self.assertEqual(result['outcome'], 'storage_observation_incomplete')
                self.assertIsNone(result['private_anonymous_verified'])
                self.assertTrue(result['abort_suite'])
                if options.get('unknown'):self.assertEqual(counts['canary'], 0)

    def test_actual_connection_tuple_requires_exclusive_selected_fd_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            selected = proc / '42'
            (selected / 'net').mkdir(parents=True);(selected / 'fd').mkdir()
            header = 'sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n'
            row = '0: 0100007F:2328 0100007F:C350 01 0:0 00:0 0 1000 0 123 1\n'
            (selected / 'net/tcp').write_text(header + row)
            (selected / 'net/tcp6').write_text(header)
            (selected / 'fd/7').symlink_to('socket:[123]')
            server = (ipaddress.ip_address('127.0.0.1'), 9000)
            client = (server[0], 50000)
            def observe():return accepted_inodes(proc, 42, server, client, {'read_bounded':read_bounded})
            self.assertEqual(observe(), 123)
            other = proc / '43/fd';other.mkdir(parents=True)
            (other / '8').symlink_to('socket:[123]')
            with self.assertRaises(ValueError):observe()
            (selected / 'fd/7').unlink()
            with self.assertRaises(ValueError):observe()
            (other / '8').unlink()
            (selected / 'net/tcp').write_text(header + row.replace('C350', 'C351'))
            with self.assertRaises(ValueError):observe()

    def test_kernel_ipv6_word_order_and_mapped_address_are_normalized(self):
        self.assertEqual(str(address('00000000000000000000000001000000', 6)), '::1')
        self.assertEqual(str(address('0000000000000000FFFF00000100007F', 6)), '127.0.0.1')
        with self.assertRaises(ValueError):address('00', 4)

    def test_guarded_transport_never_promotes_partial_or_failed_lifetime_results(self):
        for final_guard in (True, False):
            with self.subTest(final_guard=final_guard), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / 'evidence'
                with Attempt(directory, {}) as attempt:
                    def collect_stub(*args, **kwargs):
                        output = directory / 'provider-check';output.mkdir()
                        output.joinpath('stdout.log').write_text(json.dumps(dict(
                            canary_key='factory-evaluation-canary/'+'a'*32, canary_versions=[],
                            cleanup_verified=True, private_anonymous_verified=True)))
                        return dict(outcome='passed')
                    with patch('evaluation.minio_storage.collect', collect_stub):
                        result = capture_minio_storage(attempt, peer_prefix=['trusted-peer'],
                            private_binding_path='/private/binding', provider_profile=PROFILE, pid=42,
                            start_ticks='123', lifetime_check=lambda reserve:True if reserve else final_guard,
                            label='provider-check')
                    self.assertIsNone(result['private_anonymous_verified'])
                    self.assertIsNone(result['cleanup_verified'])
                    self.assertTrue(result['reported_cleanup_verified'])
                    self.assertTrue(result['abort_suite'])
                    self.assertEqual(result['canary_key'], 'factory-evaluation-canary/'+'a'*32)
                    attempt.transition('failed');attempt.finish(dict(outcome='fixture_completed'))


if __name__ == '__main__':
    unittest.main()
