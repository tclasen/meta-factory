"""Watchdog fixtures use a fake sbx executable; no host resources or model calls."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from evaluation.watchdog import Guard, validate_config


NAME = 'factory-eval-builder-0123456789abcdef'


class WatchdogTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fake = self.root / 'sbx'
        self.fake.write_text('#!' + sys.executable + '\n' + '''import sys,json
from pathlib import Path
root=Path(__file__).parent
with (root/'calls.jsonl').open('a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1]=='stop':
 if (root/'fail').exists():sys.exit(9)
 (root/'stopped').write_text(sys.argv[2])
else:
 print('SANDBOX AGENT STATUS PORTS WORKSPACE')
 if (root/'stopped').exists():print((root/'stopped').read_text()+' codex stopped')
''')
        self.fake.chmod(0o700)

    def calls(self):
        return [json.loads(line) for line in (self.root/'calls.jsonl').read_text().splitlines()]

    def test_release_independently_stops_and_verifies(self):
        guard = Guard(self.root/'guard', NAME, max_seconds=10, sbx=str(self.fake))
        result = guard.release(timeout=5)
        self.assertTrue(result['remote_termination_verified'])
        self.assertEqual(self.calls(), [['stop', NAME], ['ls']])

    def test_deadline_triggers_without_release(self):
        guard = Guard(self.root/'guard', NAME, max_seconds=.15, sbx=str(self.fake))
        guard.process.wait(timeout=5)
        result = json.loads((self.root/'guard/result.json').read_text())
        self.assertEqual(result['reason'], 'deadline')
        self.assertTrue(result['remote_termination_verified'])

    def test_failed_stop_never_claims_cleanup(self):
        (self.root/'fail').touch()
        guard = Guard(self.root/'guard', NAME, max_seconds=10, sbx=str(self.fake))
        result = guard.release(timeout=5)
        self.assertFalse(result['remote_termination_verified'])
        self.assertEqual(result['outcome'], 'cleanup_incomplete')
        self.assertEqual(result['stop']['exit_code'], 9)

    def test_owner_process_death_stops_exact_resource(self):
        code = ('import os,time\nfrom evaluation.watchdog import Guard\n'
                f'g=Guard({str(self.root/"guard")!r},{NAME!r},max_seconds=20,sbx={str(self.fake)!r})\n'
                'os._exit(0)\n')
        owner = subprocess.run([sys.executable, '-c', code], cwd=Path(__file__).resolve().parents[1], timeout=5)
        self.assertEqual(owner.returncode, 0)
        path = self.root/'guard/result.json'
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        result = json.loads(path.read_text())
        self.assertEqual(result['reason'], 'owner_exited')
        self.assertTrue(result['remote_termination_verified'])
        self.assertEqual(self.calls(), [['stop', NAME], ['ls']])

    def test_corrupt_release_still_stops_resource(self):
        guard = Guard(self.root/'guard', NAME, max_seconds=10, sbx=str(self.fake))
        (self.root/'guard/release.json').write_text('{"nonce":"incorrect"}')
        guard.process.wait(timeout=5)
        result = json.loads((self.root/'guard/result.json').read_text())
        self.assertTrue(result['remote_termination_verified'])
        self.assertEqual(result['outcome'], 'watchdog_error')

    def test_unowned_name_and_unbounded_lifetime_rejected(self):
        with self.assertRaises(ValueError):
            Guard(self.root/'guard', 'unrelated-sandbox', max_seconds=1, sbx=str(self.fake))
        with self.assertRaises(ValueError):
            Guard(self.root/'guard', NAME, max_seconds=999999, sbx=str(self.fake))
        self.assertFalse((self.root/'calls.jsonl').exists())
