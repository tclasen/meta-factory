"""Independent browser cleanup never removes a differently owned resource."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from evaluation.browser_guard import BrowserGuard


class BrowserGuardTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fake = self.root / 'docker'
        self.fake.write_text('#!' + sys.executable + '\n' + '''import json,sys
from pathlib import Path
root=Path(__file__).parent
args=sys.argv[1:]
with (root/'calls.jsonl').open('a') as f:f.write(json.dumps(args)+'\\n')
if (root/'daemon-down').exists():sys.exit(9)
path=root/'state.json';state=json.loads(path.read_text()) if path.exists() else {}
kind,operation=args[:2]
if operation=='ls':
 name=args[args.index('--filter')+1].split('=',1)[1].strip('^$').lstrip('/')
 if name in state:print(state[name]['identity'])
elif operation=='inspect':
 if args[2] not in state:sys.exit(1)
 print(json.dumps(state[args[2]]))
elif operation=='rm':
 if (root/'remove-fails').exists():sys.exit(9)
 key=args[-1]
 for name,value in list(state.items()):
  if name==key or value['identity']==key:del state[name]
 path.write_text(json.dumps(state))
else:sys.exit(8)
''')
        self.fake.chmod(0o700)

    def guard(self, seconds=10):
        return BrowserGuard(self.root / 'guard', max_seconds=seconds, docker=str(self.fake))

    def populate(self, guard, *, receipt=True):
        state = {}
        for index, (role, (kind, name)) in enumerate(guard.config['resources'].items()):
            identity = str(index + 1) * 64 if kind == 'container' else '2026-10-05T12:00:00Z'
            state[name] = {'owner': guard.config['nonce'], 'identity': identity}
            if receipt: guard.settled(role, created=True, identity=identity)
        (self.root / 'state.json').write_text(json.dumps(state))
        return state

    def test_release_removes_containers_by_id_and_volume_by_owned_name(self):
        guard = self.guard(); state = self.populate(guard)
        guard.check()
        result = guard.release(timeout=5)
        self.assertTrue(result['cleanup_verified'])
        calls = [json.loads(line) for line in (self.root / 'calls.jsonl').read_text().splitlines()]
        removals = [c for c in calls if c[1] == 'rm']
        self.assertEqual([c[0] for c in removals], ['container', 'container', 'volume'])
        for role, call in zip(('browser', 'relay'), removals):
            self.assertEqual(call[-1], state[guard.config['resources'][role][1]]['identity'])
        self.assertEqual(json.loads((self.root / 'state.json').read_text()), {})
        with self.assertRaises(RuntimeError): guard.check()

    def test_deadline_cleans_without_owner_release(self):
        guard = self.guard(.4); self.populate(guard)
        guard.process.wait(timeout=5)
        result = json.loads((guard.directory / 'result.json').read_text())
        self.assertEqual(result['reason'], 'deadline')
        self.assertTrue(result['cleanup_verified'])

    def test_unsettled_creation_is_not_cleanup_proof(self):
        guard = self.guard(); self.populate(guard, receipt=False)
        result = guard.release(timeout=5)
        self.assertFalse(result['cleanup_verified'])
        self.assertTrue(all(v['reason'] == 'creation_unsettled' for v in result['resources'].values()))
        self.assertEqual(json.loads((self.root / 'state.json').read_text()), {})

    def test_known_uncreated_resources_can_be_absent(self):
        guard = self.guard()
        for role in guard.config['resources']: guard.settled(role, created=False)
        result = guard.release(timeout=5)
        self.assertTrue(result['cleanup_verified'])

    def test_label_collision_and_replaced_identity_are_never_deleted(self):
        guard = self.guard(); state = self.populate(guard)
        browser = guard.config['resources']['browser'][1]
        relay = guard.config['resources']['relay'][1]
        state[browser]['owner'] = 'unrelated'
        state[relay]['identity'] = 'a' * 64
        (self.root / 'state.json').write_text(json.dumps(state))
        result = guard.release(timeout=5)
        self.assertFalse(result['cleanup_verified'])
        remaining = json.loads((self.root / 'state.json').read_text())
        self.assertEqual(set(remaining), {browser, relay})
        self.assertEqual(result['resources']['browser']['reason'], 'ownership_unverified')

    def test_daemon_failure_cannot_be_absence(self):
        guard = self.guard(); self.populate(guard)
        (self.root / 'daemon-down').touch()
        result = guard.release(timeout=5)
        self.assertFalse(result['cleanup_verified'])
        self.assertTrue(json.loads((self.root / 'state.json').read_text()))

    def test_corrupt_release_still_attempts_cleanup(self):
        guard = self.guard(); self.populate(guard)
        (guard.directory / 'release.json').write_text('{"nonce":"invalid"}')
        guard.process.wait(timeout=5)
        result = json.loads((guard.directory / 'result.json').read_text())
        self.assertEqual(result['reason'], 'watchdog_error')
        self.assertTrue(result['cleanup_verified'])

    def test_owner_death_cleans_settled_resources(self):
        code = ('import json,os\nfrom pathlib import Path\nfrom evaluation.browser_guard import BrowserGuard\n'
                f'g=BrowserGuard({str(self.root / "guard")!r},max_seconds=10,docker={str(self.fake)!r})\n'
                'state={}\nfor index,(role,(kind,name)) in enumerate(g.config["resources"].items()):\n'
                ' identity=str(index+1)*64 if kind=="container" else "fixture-created-at"\n'
                ' state[name]={"owner":g.config["nonce"],"identity":identity}\n'
                ' g.settled(role,created=True,identity=identity)\n'
                f'Path({str(self.root / "state.json")!r}).write_text(json.dumps(state))\n'
                'os._exit(0)\n')
        subprocess.run([sys.executable, '-c', code], check=True, timeout=5,
                       cwd=Path(__file__).resolve().parents[1])
        path = self.root / 'guard/result.json'
        stop = time.monotonic() + 5
        while not path.exists() and time.monotonic() < stop: time.sleep(.02)
        result = json.loads(path.read_text())
        self.assertTrue(result['cleanup_verified'])
        self.assertEqual(result['reason'], 'owner_exited')

    def test_invalid_lifetime_has_no_side_effects(self):
        for seconds in (True, -1, 5401):
            with self.assertRaises(ValueError): self.guard(seconds)
        self.assertFalse((self.root / 'guard').exists())
