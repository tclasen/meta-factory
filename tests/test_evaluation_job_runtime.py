"""Socket-level lifetime, independent enumeration and redaction controls."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from evaluation.job_broker import JobObservationError, read_job
from evaluation.job_runtime import JobRuntime


class JobRuntimeTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.box = SimpleNamespace(name='test-grader', stopped=False)
        self.guard = SimpleNamespace(directory=self.root / 'guard',
                                     process=SimpleNamespace(poll=lambda: None))
        self.guard.directory.mkdir()
        self.now = [100, 100]
        self.export_id = str(uuid.uuid4())
        self.value = dict(export_id=self.export_id, status='running', processing_attempts=4,
                          active_lease=True, lease_fingerprint='a'*64, completion_events=2,
                          published_artifacts=999, password='private-password-canary')
        self.physical_count = 2
        self.calls = []
        self.actions = {}

    def callback(self, name, value=None):
        def execute(*args, timeout):
            self.calls.append((name, args, timeout))
            if name in self.actions:
                self.actions[name]()
            return value() if value else None
        return execute

    def runtime(self):
        runtime = JobRuntime(self.root / ('jobs-' + uuid.uuid4().hex), self.box, self.guard,
            database_read=self.callback('database', lambda: self.value),
            artifact_count=self.callback('objects', lambda: self.physical_count),
            database_peer_check=self.callback('database-peer'),
            storage_peer_check=self.callback('storage-peer'),
            monotonic_deadline=200, wall_deadline=200,
            monotonic=lambda: self.now[0], wall=lambda: self.now[1])
        self.addCleanup(runtime.close)
        return runtime

    def read(self, runtime):
        return read_job(runtime.broker.configuration, self.export_id)

    def test_physical_counts_override_database_metadata_and_evidence_is_private(self):
        runtime = self.runtime()
        observation = self.read(runtime)
        self.assertEqual(observation['published_artifacts'], 2)
        self.assertEqual(observation['processing_attempts'], 4)
        self.assertEqual(observation['completion_events'], 2)
        self.assertNotIn('password', observation)
        self.assertEqual([call[0] for call in self.calls], [
            'database-peer', 'storage-peer', 'database', 'database-peer',
            'storage-peer', 'objects', 'database-peer', 'storage-peer'])
        self.assertEqual([call[2] for call in self.calls if call[0] in ('database', 'objects')], [15, 15])
        for path in runtime.directory.rglob('*'):
            if path.is_file():
                contents = path.read_text()
                for private in (self.export_id, 'a'*64, 'private-password-canary'):
                    self.assertNotIn(private, contents)
        result = next(runtime.directory.glob('read-*/result.json'))
        self.assertEqual(json.loads(result.read_text())['outcome'], 'job_observed')

    def test_each_clock_and_lifetime_state_refuses_before_any_callback(self):
        runtime = self.runtime()
        for index in range(2):
            self.now[index] = 161
            with self.assertRaises(JobObservationError): self.read(runtime)
            self.now[index] = 100
        for filename in ('release.json', 'result.json'):
            path = self.guard.directory / filename
            path.touch()
            with self.assertRaises(JobObservationError): self.read(runtime)
            path.unlink()
        self.box.stopped = True
        with self.assertRaises(JobObservationError): self.read(runtime)
        self.box.stopped = False
        self.guard.process.poll = lambda: 0
        with self.assertRaises(JobObservationError): self.read(runtime)
        self.guard.process.poll = lambda: None
        runtime.owner_pid = -1
        with self.assertRaises(JobObservationError): self.read(runtime)
        self.assertEqual(self.calls, [])

    def test_revocation_after_each_callback_suppresses_success_and_later_reads(self):
        for name in ('database-peer', 'storage-peer', 'database', 'objects'):
            with self.subTest(callback=name):
                self.calls.clear(); self.actions.clear()
                runtime = self.runtime()
                self.actions[name] = runtime.revoked.set
                with self.assertRaises(JobObservationError): self.read(runtime)
                self.assertEqual(self.calls[-1][0], name)
                runtime.close()

    def test_invalid_durable_data_prevents_enumeration(self):
        runtime = self.runtime()
        for key, malformed in (('export_id', str(uuid.uuid4())), ('active_lease', 1),
                               ('lease_fingerprint', 'raw-secret'), ('processing_attempts', -1)):
            previous = self.value[key]; self.value[key] = malformed
            with self.assertRaises(JobObservationError): self.read(runtime)
            self.value[key] = previous
        self.assertNotIn('objects', [call[0] for call in self.calls])

    def test_invalid_physical_count_and_private_callback_errors_are_inconclusive(self):
        runtime = self.runtime()
        for malformed in (True, -1, None, {'count': 1}):
            self.physical_count = malformed
            with self.assertRaises(JobObservationError): self.read(runtime)
        def fail(): raise RuntimeError('private-password-canary')
        self.actions['objects'] = fail
        with self.assertRaises(JobObservationError): self.read(runtime)
        for path in runtime.directory.rglob('*'):
            if path.is_file(): self.assertNotIn('private-password-canary', path.read_text())

    def test_insufficient_reserve_refuses_endpoint_creation(self):
        self.now[1] = 161
        with self.assertRaises(JobObservationError): self.runtime()
        self.assertEqual(list(self.root.glob('jobs-*')), [])
