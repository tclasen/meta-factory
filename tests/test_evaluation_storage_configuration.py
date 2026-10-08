"""Selected startup values stay private and cannot imply application use."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.storage_configuration_probe import mapping, observe, selected_environment
from evaluation.storage_configuration import capture_storage_configuration
from evaluation.evidence import Attempt


CONFIG = dict(endpoint='http://127.0.0.1:9000', bucket='fixture-bucket', region='us-east-1',
              access_key='private-access-value', secret_key='private-secret-value', session_token=None)
SELECTED = {key:'APP_'+key.upper() for key in CONFIG};SELECTED['session_token'] = None


class ConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.proc = Path(self.temporary.name);(self.proc/'42').mkdir()
        self.path = self.proc/'42/environ';self.write(CONFIG)

    def write(self, config):
        self.path.write_bytes(b'UNRELATED_SECRET=never-log-this\0'+b''.join(
            (SELECTED[key]+'='+value).encode()+b'\0' for key,value in config.items() if value is not None))

    def observe(self, identity=None, **changes):
        options = dict(config=CONFIG, selected=SELECTED, pid=42, start_ticks='123', executable_sha256='a'*64,
                       address='127.0.0.1', port=9001, identity=identity or (lambda *args,**kwargs:{'same':'identity'}), proc=self.proc)
        options.update(changes);return observe(**options)

    def test_matching_startup_configuration_emits_no_credentials_or_unrelated_values(self):
        result = self.observe();raw = json.dumps(result)
        self.assertTrue(result['snapshot_stable']);self.assertTrue(result['selected_credentials_matched'])
        for field in ('application_use_verified','current_configuration_verified','deployment_attribution_verified'):
            self.assertFalse(result[field])
        for secret in (CONFIG['access_key'],CONFIG['secret_key'],'never-log-this'):
            self.assertNotIn(secret,raw)

    def test_each_changed_or_missing_selected_value_refuses_comparison(self):
        for key in ('endpoint','bucket','region','access_key','secret_key'):
            with self.subTest(key=key):
                altered = dict(CONFIG);altered[key] = 'wrong-value';self.write(altered)
                with self.assertRaises(ValueError):self.observe()
        self.path.write_bytes(b'UNRELATED_SECRET=never-log-this\0')
        with self.assertRaises(ValueError):self.observe()

    def test_environment_layout_duplicates_and_limits_are_refused(self):
        for raw in (self.path.read_bytes()+b'APP_BUCKET=duplicate\0',b'broken-entry',b'x'*65537,
                    b'X=v\0'*2049,b'APP_SECRET_KEY='+b'x'*4097):
            with self.subTest(size=len(raw)):
                self.path.write_bytes(raw)
                with self.assertRaises(ValueError):selected_environment(self.path,SELECTED.values())

    def test_mapping_and_optional_session_settings_are_explicit(self):
        for altered in (dict(SELECTED,bucket=SELECTED['endpoint']),dict(SELECTED,endpoint='invalid-name'),{}):
            with self.assertRaises(ValueError):mapping(altered)
        with self.assertRaises(ValueError):self.observe(config=dict(CONFIG,session_token='private-session'))
        selected = dict(SELECTED,session_token='APP_SESSION_TOKEN')
        self.assertTrue(self.observe(selected=selected)['snapshot_stable'])
        self.path.write_bytes(self.path.read_bytes()+b'APP_SESSION_TOKEN=unexpected\0')
        with self.assertRaises(ValueError):self.observe(selected=selected)

    def test_process_or_selected_environment_drift_refuses_comparison(self):
        for change in ('identity','environment'):
            self.write(CONFIG);calls = [0]
            def identity(*args,**kwargs):
                calls[0] += 1
                if calls[0]==2 and change=='environment':self.write(dict(CONFIG,bucket='changed-bucket'))
                return {'revision':calls[0] if change=='identity' else 1}
            with self.assertRaises(ValueError):self.observe(identity=identity)

    def test_sanitized_transport_result_is_invalidated_when_lifetime_ends(self):
        with Attempt(self.proc/'evidence',{}) as attempt:
            value=self.observe()
            def collect(*args,**kwargs):
                output=attempt.directory/'configuration-check';output.mkdir()
                (output/'stdout.log').write_text(json.dumps(value));return dict(outcome='passed')
            with patch('evaluation.storage_configuration.collect',collect):
                result=capture_storage_configuration(attempt,peer_prefix=['trusted-peer'],
                    private_binding_path='/private/config',selected=SELECTED,pid=42,start_ticks='123',
                    executable_sha256='a'*64,address='127.0.0.1',port=9001,
                    lifetime_check=lambda reserve:bool(reserve),label='configuration-check')
            self.assertEqual(result['outcome'],'storage_startup_configuration_incomplete')
            self.assertFalse(result['snapshot_stable']);self.assertFalse(result['selected_credentials_matched'])
            attempt.transition('failed');attempt.finish(dict(outcome='fixture_completed'))


if __name__=='__main__':unittest.main()
