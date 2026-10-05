"""Guard private job observations across independent database and storage reads."""
import os
from pathlib import Path
import threading
import time
import uuid

from .evidence import Attempt, atomic_json, positive
from .job_broker import JobBroker, JobObservationError, export_identity, project

READ_RESERVE = 40
READ_TIMEOUT = 15
DATABASE_FIELDS = {'export_id', 'status', 'processing_attempts', 'active_lease',
                   'lease_fingerprint', 'completion_events'}


class JobRuntime:
    """Trusted callbacks must enforce timeouts and independently bind actual peers.

    database_read(export_id, timeout=...) returns normalized durable job/lease and
    completion-event data. artifact_count(export_id, timeout=...) independently
    enumerates physical published objects, never database artifact metadata.
    Each peer_check(timeout=...) verifies its exact bound live peer. No callback
    is selected from builder output or grader requests. These callbacks are a
    reviewed operator integration contract, not implemented discovery/readers.
    """
    def __init__(self, directory, sandbox, guard, *, database_read, artifact_count,
                 database_peer_check, storage_peer_check, monotonic_deadline,
                 wall_deadline, monotonic=time.monotonic, wall=time.time):
        positive(monotonic_deadline, 'job monotonic deadline')
        positive(wall_deadline, 'job wall deadline')
        if not all(callable(callback) for callback in (
                database_read, artifact_count, database_peer_check, storage_peer_check)):
            raise ValueError('Job observations require independent trusted readers and peer checks')
        self.database_read, self.artifact_count = database_read, artifact_count
        self.database_peer_check, self.storage_peer_check = database_peer_check, storage_peer_check
        self.sandbox, self.guard = sandbox, guard
        self.owner_pid = os.getpid()
        self.monotonic_deadline, self.wall_deadline = monotonic_deadline, wall_deadline
        self.monotonic, self.wall = monotonic, wall
        self.revoked = threading.Event()
        self.check(READ_RESERVE)
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        atomic_json(self.directory / 'scope.json', {'sandbox': sandbox.name, 'wall_deadline': wall_deadline})
        self.broker = JobBroker(self._read)

    def check(self, allowance):
        if (self.revoked.is_set() or os.getpid() != self.owner_pid or self.sandbox.stopped
                or self.guard.process.poll() is not None
                or (self.guard.directory / 'release.json').exists()
                or (self.guard.directory / 'result.json').exists()
                or min(self.monotonic_deadline - self.monotonic(),
                       self.wall_deadline - self.wall()) < allowance):
            raise JobObservationError('Job observation lifetime unavailable')

    def checked_peers(self, allowance):
        self.check(allowance)
        for callback in (self.database_peer_check, self.storage_peer_check):
            callback(timeout=1)
            self.check(allowance)

    def _read(self, export_id):
        export_identity(export_id)
        self.checked_peers(READ_RESERVE)
        with Attempt(self.directory / ('read-' + uuid.uuid4().hex),
                     {'sandbox': self.sandbox.name, 'operation': 'job_read'}) as attempt:
            attempt.transition('preflight')
            result = {'outcome': 'job_observation_incomplete'}
            try:
                value = self.database_read(export_id, timeout=READ_TIMEOUT)
                self.checked_peers(READ_TIMEOUT + 5)
                if not isinstance(value, dict) or not DATABASE_FIELDS <= value.keys():
                    raise JobObservationError('Durable job observation incomplete')
                # Validate durable data before invoking the physical enumerator.
                durable = {key: value[key] for key in DATABASE_FIELDS}
                project(dict(durable, published_artifacts=0), export_id)
                count = self.artifact_count(export_id, timeout=READ_TIMEOUT)
                self.checked_peers(1)
                observation = project(dict(durable, published_artifacts=count), export_id)
                result['outcome'] = 'job_observed'
                return observation
            except BaseException as error:
                result['error_type'] = type(error).__name__
                raise
            finally:
                # No job identity, lease data, credentials or callback text in logs.
                attempt.transition('failed')
                attempt.finish(result)

    def close(self):
        self.revoked.set()
        self.broker.close()
