"""Protected journey signatures, source identity, and secret-safe worker outcomes."""
import hashlib
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from evaluation.browser_worker import execute, invoke, load_case
from evaluation.verdicts import Inconclusive, Untested


class BrowserWorkerTest(unittest.TestCase):
    def setUp(self):
        self.browser = Mock()
        self.page = self.browser.new_context.return_value.new_page.return_value
        self.requests = object()
        self.target = {'secret': 'private-canary'}
        self.case = dict(id='journey', function='journey', browser='page')

    def test_all_declared_signatures_and_observations_discarded(self):
        for mode in ('page', 'page_request', 'browser', 'browser_request'):
            self.case['browser'] = mode
            fn = Mock(return_value={'private': 'private-canary'})
            result = invoke(self.case, SimpleNamespace(journey=fn), self.browser, self.requests, self.target)
            args = [self.page if mode.startswith('page') else self.browser, self.target]
            if mode.endswith('_request'): args.append(self.requests)
            fn.assert_called_once_with(*args)
            self.assertEqual(result, {'case_id': 'journey', 'verdict': 'pass'})
        self.assertEqual(self.browser.new_context.return_value.close.call_count, 2)
        self.page.set_default_timeout.assert_called_with(10000)

    def test_fixture_restoration_assertion_and_other_signals(self):
        class BrowserRestorationError(RuntimeError): pass
        class BrowserFixtureUnavailable(RuntimeError): pass
        for error, verdict, abort in ((BrowserRestorationError, 'inconclusive', True),
                (BrowserFixtureUnavailable, 'inconclusive', False), (AssertionError, 'fail', False),
                (RuntimeError, 'inconclusive', False), (Inconclusive, 'inconclusive', False),
                (Untested, 'untested', False)):
            module = SimpleNamespace(journey=Mock(side_effect=error('private-canary')),
                BrowserRestorationError=BrowserRestorationError, BrowserFixtureUnavailable=BrowserFixtureUnavailable)
            result = invoke(self.case, module, self.browser, self.requests, self.target)
            self.assertEqual(result['verdict'], verdict)
            self.assertEqual(result.get('abort_suite', False), abort)
            self.assertNotIn('private-canary', json.dumps(result))

    def test_context_cleanup_overrides_success_and_failure(self):
        self.browser.new_context.return_value.close.side_effect = RuntimeError('private-canary')
        for error in (None, AssertionError('private-canary')):
            result = invoke(self.case, SimpleNamespace(journey=Mock(side_effect=error, return_value=None)),
                            self.browser, self.requests, self.target)
            self.assertEqual(result['verdict'], 'inconclusive')
            self.assertTrue(result['abort_suite'])
            self.assertNotIn('private-canary', json.dumps(result))

    def test_unexpected_return_is_not_a_pass(self):
        result = invoke(self.case, SimpleNamespace(journey=lambda *a: True), self.browser, self.requests, self.target)
        self.assertEqual(result['verdict'], 'inconclusive')

    def test_hashed_manifest_and_all_sources_checked_before_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'journey.py'
            source.write_text('def journey(browser, target):\n    return {}\n')
            manifest = root / 'suite.json'
            document = dict(schema_version=1, files={'journey.py': hashlib.sha256(source.read_bytes()).hexdigest()},
                            cases=[dict(self.case, source='journey.py')])
            manifest.write_text(json.dumps(document))
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            case, module = load_case(root, digest, 'journey')
            self.assertEqual(module.journey(None, None), {})
            self.assertEqual(case['browser'], 'page')
            with self.assertRaises(ValueError): load_case(root, '0' * 64, 'journey')
            with self.assertRaises(ValueError): load_case(root, digest, 'missing')
            source.write_text('raise AssertionError("must never import changed source")')
            with self.assertRaises(ValueError): load_case(root, digest, 'journey')

    def test_unsafe_origin_or_missing_isolation_never_starts_browser(self):
        factory = Mock()
        for origin in ('https://127.0.0.1:1234', 'http://localhost:1234', 'http://127.0.0.1:1234/',
                       'http://user:password@127.0.0.1:1234', 'http://other.invalid:1234'):
            with patch('evaluation.browser_worker.isolation_check'):
                result = execute('missing', 'digest', 'journey', {'base_url': origin}, socket_path='/channel/app.sock',
                                 wall_deadline=9999999999, playwright_factory=factory)
            self.assertEqual(result['verdict'], 'inconclusive')
        with patch('evaluation.browser_worker.isolation_check', side_effect=RuntimeError('private-canary')):
            result = execute('missing', 'digest', 'journey', {}, socket_path='/channel/app.sock',
                             wall_deadline=9999999999, playwright_factory=factory)
        self.assertNotIn('private-canary', json.dumps(result))
        factory.assert_not_called()

    def test_worker_cleanup_and_sandbox_launch(self):
        for broken in (None, 'browser', 'relay'):
            with self.subTest(broken=broken), ExitStack() as stack:
                stack.enter_context(patch('evaluation.browser_worker.isolation_check'))
                stack.enter_context(patch('evaluation.browser_worker.load_case', return_value=(
                    dict(self.case, browser='browser'), SimpleNamespace(journey=lambda *a: {}))))
                relay = stack.enter_context(patch('evaluation.browser_worker.RelayServer')).return_value
                relay.observation.return_value = {'completed': 1}
                thread = stack.enter_context(patch('evaluation.browser_worker.threading.Thread')).return_value
                thread.is_alive.return_value = False
                factory = Mock()
                manager = MagicMock()
                factory.return_value = manager
                engine = manager.__enter__.return_value
                browser = engine.chromium.launch.return_value
                browser.version = 'synthetic-version'
                if broken == 'browser': browser.close.side_effect = RuntimeError('private-canary')
                if broken == 'relay': relay.server_close.side_effect = RuntimeError('private-canary')
                result = execute('unused', 'digest', 'journey', {'base_url': 'http://127.0.0.1:18080'},
                                 socket_path='/channel/app.sock', wall_deadline=9999999999,
                                 playwright_factory=factory)
                engine.chromium.launch.assert_called_once_with(headless=True, chromium_sandbox=True)
                browser.close.assert_called_once()
                relay.shutdown.assert_called_once()
                relay.server_close.assert_called_once()
                self.assertEqual(result['verdict'], 'pass' if broken is None else 'inconclusive')
                self.assertEqual(result.get('abort_suite', False), broken is not None)
                self.assertNotIn('private-canary', json.dumps(result))
