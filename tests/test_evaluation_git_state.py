"""Native Git persistence/recovery and immutable seed-input checks (REQ-007)."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from evaluation.git_state import TRACKER_PATH, render_git_seed


class GitStateTest(unittest.TestCase):
    def setUp(self):
        self.manifest = dict(schema_version=1, specification_version='fixture-v1', packages=[
            dict(id='WP-002', title='Second frozen package', criteria=['AC-002']),
            dict(id='WP-001', title='First frozen package', criteria=['AC-001'])])

    def render(self, manifest=None):
        data = json.dumps(self.manifest if manifest is None else manifest).encode()
        return render_git_seed(data, hashlib.sha256(data).hexdigest())

    def test_seed_preserves_specification_order_identity_and_todo_initialization(self):
        original = json.dumps(self.manifest)
        seed = self.render().decode()
        self.assertEqual(seed, '# Task state\nSchema: 1\nSpecification: fixture-v1\n\n'
            '## WP-002 — Second frozen package\nStatus: todo\nProgress:\nNext:\n\n'
            '## WP-001 — First frozen package\nStatus: todo\nProgress:\nNext:\n')
        self.assertEqual(json.dumps(self.manifest), original)
        self.assertNotIn('AC-002', seed)

    def test_changed_or_unbound_bytes_are_rejected(self):
        data = json.dumps(self.manifest).encode()
        for payload, digest in ((data + b' ', hashlib.sha256(data).hexdigest()),
                                (data, '0' * 64), (data, None), ('not bytes', '0' * 64),
                                (b'x' * (1024 * 1024 + 1), '0' * 64)):
            with self.subTest(digest=digest):
                with self.assertRaises(ValueError):
                    render_git_seed(payload, digest)

    def test_ambiguous_or_injectable_package_identity_is_rejected(self):
        for field, value in (('title', 'Title\nStatus: done'), ('title', '\u2028new section'),
                             ('title', ' hidden '), ('title', '\x00'), ('title', ''),
                             ('id', '../WP-001'), ('id', 'WP-001\n')):
            manifest = json.loads(json.dumps(self.manifest))
            manifest['packages'][0][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.render(manifest)
        manifest = dict(self.manifest, packages=[self.manifest['packages'][0]] * 2)
        with self.assertRaises(ValueError):
            self.render(manifest)
        for override in (dict(schema_version=True), dict(packages=[]),
                         dict(specification_version='v1\nSchema: 2')):
            with self.assertRaises(ValueError):
                self.render(dict(self.manifest, **override))
        data = b'{"schema_version":1,"schema_version":1}'
        with self.assertRaises(ValueError):
            render_git_seed(data, hashlib.sha256(data).hexdigest())

    def test_native_transitions_commits_and_fresh_checkout_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); project = root / 'project'; project.mkdir()
            def git(*args, cwd=project):
                return subprocess.run(['git', *args], cwd=cwd, check=True,
                    capture_output=True, text=True, timeout=10).stdout
            git('init', '--initial-branch=main')
            git('config', 'user.name', 'Native state fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            git('config', 'commit.gpgsign', 'false')
            git('config', 'core.hooksPath', str(root / 'no-hooks'))
            specification = project / 'spec-fixture.json'
            spec_bytes = json.dumps(self.manifest).encode(); specification.write_bytes(spec_bytes)
            tracker = project / TRACKER_PATH; tracker.parent.mkdir(parents=True)
            tracker.write_bytes(self.render())
            git('add', 'spec-fixture.json', TRACKER_PATH)
            git('commit', '-m', 'chore(fixture): seed immutable inputs and state')
            history = [git('rev-parse', 'HEAD').strip()]
            for state in ('in_progress', 'blocked', 'in_progress', 'done', 'in_progress'):
                current = tracker.read_text()
                start = current.index('Status: '); end = current.index('\n', start)
                tracker.write_text(current[:start] + 'Status: ' + state + current[end:])
                git('add', TRACKER_PATH)
                git('commit', '-m', 'chore(state): update task state')
                history.append(git('rev-parse', 'HEAD').strip())
                self.assertIn('Status: ' + state, git('show', 'HEAD:' + TRACKER_PATH))
                self.assertEqual(specification.read_bytes(), spec_bytes)
                self.assertEqual(git('status', '--porcelain'), '')
            checkout = root / 'recovered'
            git('clone', '--no-hardlinks', str(project), str(checkout), cwd=root)
            self.assertEqual((checkout / TRACKER_PATH).read_bytes(), tracker.read_bytes())
            self.assertEqual(git('show', history[0] + ':' + TRACKER_PATH), self.render().decode())
            # A failed native write is retained, not transformed into a new arm.
            lock = project / '.git/index.lock'; lock.write_text('fixture ownership lock')
            tracker.write_text(tracker.read_text().replace('Next:', 'Next: retry native write', 1))
            failed = subprocess.run(['git', 'add', TRACKER_PATH], cwd=project,
                                    capture_output=True, timeout=10)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(git('rev-parse', 'HEAD').strip(), history[-1])
            self.assertIn('retry native write', tracker.read_text())
            self.assertEqual(specification.read_bytes(), spec_bytes)
