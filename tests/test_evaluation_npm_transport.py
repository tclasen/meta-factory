"""Native-client collection cannot turn availability or stale bindings into success."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.npm_transport import NpmTransport, SYNC_ERROR


class NpmTransportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.attempt = Attempt(self.root/'attempt', {})
        self.addCleanup(self.attempt.close)
        self.binding = {key: hashlib.sha256(key.encode()).hexdigest() for key in
            ('capture_sha256', 'manifest_sha256', 'lock_sha256', 'configuration_sha256', 'tool_context_sha256')}
        self.reserves = []

    def client(self, ci, version="print('10.9.2')", **kwargs):
        script = self.root/('client-'+str(len(list(self.root.glob('client-*'))))+'.py')
        script.write_text("import sys,time\nif sys.argv[-1]=='--version':\n " +
                          version.replace('\n', '\n ') + '\nelse:\n ' + ci.replace('\n', '\n '))
        def check(binding, reserve):
            self.assertEqual(binding, self.binding)
            self.reserves.append(reserve)
            return True
        kwargs.setdefault('check', check)
        kwargs.setdefault('cleanup', lambda: True)
        return NpmTransport(self.attempt, [sys.executable, str(script)], self.binding,
                            cwd=self.root, **kwargs)

    def test_success_fixed_flags_binding_and_private_diagnostics(self):
        output = self.client("assert sys.argv[-5:]==['ci','--ignore-scripts','--no-audit','--no-fund','--offline']\nprint('PRIVATE_URL_WITH_SECRET')")()
        self.assertTrue(output['native_consistency'])
        self.assertTrue(output['bindings_verified'])
        self.assertTrue(output['remote_install_absent_verified'])
        self.assertEqual(self.reserves, [65, 5, 0])
        self.assertEqual(len(output['commands']), 3)
        for key in ('installed_environment_bound', 'artifact_integrity_verified', 'build_consumption_verified'):
            self.assertFalse(output[key])
        self.assertNotIn('PRIVATE_URL_WITH_SECRET', '\n'.join(p.read_text() for p in self.attempt.directory.rglob('*') if p.is_file()))

    def test_only_explicit_native_sync_error_produces_false(self):
        stderr = 'npm error code EUSAGE\n'+SYNC_ERROR.decode()+' Please update your lock file.\nPRIVATE_DIAGNOSTIC'
        value = self.client('print('+repr(stderr)+',file=sys.stderr)\nsys.exit(1)')()
        self.assertFalse(value['native_consistency'])
        self.assertEqual(value['outcome'], 'npm_consistency_observed')
        self.assertNotIn('PRIVATE_DIAGNOSTIC', json.dumps(value))
        for diagnostic in ('npm error code ENOTCACHED', 'npm error code EUSAGE\nUnrelated usage failure',
                           'npm error code UNKNOWN_SECRET_CODE\n'+SYNC_ERROR.decode(),
                           'npm error code EUSAGE\nnpm error code ENOTCACHED\n'+SYNC_ERROR.decode()):
            with self.subTest(diagnostic=diagnostic):
                value = self.client('print('+repr(diagnostic)+',file=sys.stderr)\nsys.exit(1)')()
                self.assertIsNone(value['native_consistency'])
                self.assertEqual(value['outcome'], 'npm_native_unavailable')
                self.assertNotIn('UNKNOWN_SECRET_CODE', json.dumps(value))

    def test_failed_initial_or_final_binding_and_cleanup_are_incomplete(self):
        for fail_at in (1, 2, 3):
            calls = []
            def check(binding, reserve):
                calls.append(reserve)
                return len(calls) != fail_at
            value = self.client('pass', check=check)()
            self.assertIsNone(value['native_consistency'])
            self.assertFalse(value['bindings_verified'])
            self.assertTrue(value['remote_install_absent_verified'])
        for cleanup in (lambda: False, lambda: 1):
            value = self.client('pass', cleanup=cleanup)()
            self.assertIsNone(value['native_consistency'])
            self.assertFalse(value['remote_install_absent_verified'])

    def test_unsupported_or_changed_tool_and_failed_commands_remain_unknown(self):
        for version in ("print('11.0.0')", "print('10.9.2'); print('PRIVATE_ERROR',file=sys.stderr)"):
            value = self.client('pass', version=version)()
            self.assertIsNone(value['native_consistency'])
            self.assertEqual(len(value['commands']), 1)
        state = self.root/'version-count'
        version = ('from pathlib import Path\np=Path('+repr(str(state))+')\n' +
                   'count=int(p.read_text())+1 if p.exists() else 1\np.write_text(str(count))\n' +
                   "print('10.9.2' if count==1 else '10.9.3')")
        value = self.client('pass', version=version)()
        self.assertIsNone(value['native_consistency'])
        self.assertFalse(value['bindings_verified'])

    def test_timeout_and_output_bounds_have_receipts_and_cleanup(self):
        for ci, kwargs, timeout in (('time.sleep(2)', {}, .3),
                                    ("print('x'*2048)", {'max_output_bytes': 1024}, 5)):
            value = self.client(ci, **kwargs)(timeout=timeout)
            self.assertIsNone(value['native_consistency'])
            self.assertTrue(value['client_groups_absent'])
            self.assertTrue(value['remote_install_absent_verified'])
            self.assertIn(value['commands'][-1]['outcome'], ('timeout', 'output_limit'))
        self.assertEqual(len(list(self.attempt.directory.glob('npm-*/result.json'))), 2)

    def test_guard_mutations_are_isolated_and_interrupt_has_receipt(self):
        def check(binding, reserve):
            binding.clear()
            return True
        value = self.client('pass', check=check)()
        self.assertTrue(value['native_consistency'])
        self.assertEqual(len(self.binding), 5)
        def interrupt(binding, reserve):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.client('pass', check=interrupt)()
        records = [json.loads(p.read_text()) for p in self.attempt.directory.glob('npm-*/result.json')]
        self.assertEqual(sum(r['outcome']=='interrupted' for r in records), 1)
        self.assertTrue(all(r['remote_install_absent_verified'] for r in records))

    def test_cleanup_and_final_guard_interrupts_preserve_receipts(self):
        def interrupt():
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.client('pass', cleanup=interrupt)()
        calls = []
        def check(binding, reserve):
            calls.append(reserve)
            if len(calls) == 3:
                raise KeyboardInterrupt
            return True
        with self.assertRaises(KeyboardInterrupt):
            self.client('pass', check=check)()
        records = [json.loads(p.read_text()) for p in self.attempt.directory.glob('npm-*/result.json')]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r['outcome']=='interrupted' and r['native_consistency'] is None for r in records))


if __name__ == '__main__':
    unittest.main()
