"""Guarded parent-owned metadata reads for protected authentication audit cases."""
import copy
import os
from pathlib import Path
import threading
import time
import uuid

from .audit_broker import AuditBroker, AuditObservationError, project, request_values
from .database_probe import audit_read_sql, identifier
from .database_transport import DatabaseTransport
from .evidence import Attempt, atomic_json, positive

READ_RESERVE = 25


class AuditRuntime:
    def __init__(self, directory, sandbox, guard, *, audit_binding, database_peer,
                 database_peer_check, monotonic_deadline, wall_deadline,
                 monotonic=time.monotonic, wall=time.time,
                 transport_factory=DatabaseTransport):
        positive(monotonic_deadline, 'audit monotonic deadline')
        positive(wall_deadline, 'audit wall deadline')
        required = {'schema', 'table', 'table_oid', 'fields', 'database_name',
                    'operator_user', 'operator_session_user'}
        if (not isinstance(audit_binding, dict) or set(audit_binding) != required
                or not isinstance(database_peer, dict)
                or set(database_peer) != {'prefix', 'services', 'cwd'}
                or not callable(database_peer_check)):
            raise ValueError('Audit observations require an operator binding and verified peer')
        binding = copy.deepcopy(audit_binding)
        for key in ('database_name', 'operator_user', 'operator_session_user'):
            identifier(binding[key])
        # Validate the entire SQL mapping before creating an endpoint.
        audit_read_sql(binding['schema'], binding['table'], binding['table_oid'],
                       binding['fields'], [str(uuid.UUID(int=0))])
        self.binding = binding
        self.peer = copy.deepcopy(database_peer)
        self.peer_check = database_peer_check
        self.transport_factory = transport_factory
        self.sandbox, self.guard = sandbox, guard
        self.owner_pid = os.getpid()
        self.monotonic_deadline, self.wall_deadline = monotonic_deadline, wall_deadline
        self.monotonic, self.wall = monotonic, wall
        self.revoked = threading.Event()
        self.check(READ_RESERVE)
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        atomic_json(self.directory / 'scope.json', {'sandbox': sandbox.name,
                                                   'wall_deadline': wall_deadline})
        self.broker = AuditBroker(self._read)

    def check(self, allowance):
        if (self.revoked.is_set() or os.getpid() != self.owner_pid or self.sandbox.stopped
                or self.guard.process.poll() is not None
                or (self.guard.directory / 'release.json').exists()
                or (self.guard.directory / 'result.json').exists()
                or min(self.monotonic_deadline - self.monotonic(),
                       self.wall_deadline - self.wall()) < allowance):
            raise AuditObservationError('Audit observation lifetime unavailable')

    def checked_peer(self, allowance):
        self.check(allowance)
        self.peer_check(allowance)
        self.check(allowance)

    def _read(self, correlations, forbidden_values):
        request_values(correlations, forbidden_values)
        self.checked_peer(READ_RESERVE)
        binding = self.binding
        sql = audit_read_sql(binding['schema'], binding['table'], binding['table_oid'],
                             binding['fields'], correlations, forbidden_values=forbidden_values)
        with Attempt(self.directory / ('read-' + uuid.uuid4().hex),
                     {'sandbox': self.sandbox.name, 'operation': 'audit_read'}) as attempt:
            attempt.transition('preflight')
            result = {'outcome': 'audit_observation_incomplete'}
            try:
                transport = self.transport_factory(attempt, self.peer['prefix'], self.peer['services'],
                                                   check=self.checked_peer, cwd=self.peer['cwd'])
                value = transport('operator', sql, timeout=15)
                self.checked_peer(5)
                if (value.get('database_name') != binding['database_name']
                        or value.get('current_user') != binding['operator_user']
                        or value.get('session_user') != binding['operator_session_user']
                        or type(value.get('relation_oid')) is not int
                        or value['relation_oid'] != binding['table_oid']):
                    raise AuditObservationError('Audit database identity changed')
                observation = project(value)
                result['outcome'] = 'audit_observed'
                return observation
            except BaseException as error:
                result['error_type'] = type(error).__name__
                raise
            finally:
                # Metadata and text controls must never enter controller evidence.
                attempt.transition('failed')
                attempt.finish(result)

    def close(self):
        self.revoked.set()
        self.broker.close()
