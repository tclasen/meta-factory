"""Bind parent-owned fault requests to one guarded grading sandbox."""

from contextlib import contextmanager
import copy
import os
from pathlib import Path
import threading
import time
import uuid

from .evidence import Attempt, atomic_json, positive
from .fault_broker import FaultBroker
from .faults import FaultSetupError, suspended_workload
from .workload_probe import KINDS, NAME
from .workloads import workload_operation


COMMAND_ALLOWANCE = 150  # 135-second command ceiling plus scheduling allowance.
FAULT_ALLOWANCE = 630    # Four commands, 60-second body, plus scheduling allowance.


class FaultRuntime:
    def __init__(self, directory, sandbox, guard, workloads, kubectl_prefix, *,
                 monotonic_deadline, wall_deadline, operation=workload_operation,
                 monotonic=time.monotonic, wall=time.time):
        positive(monotonic_deadline, 'fault monotonic deadline')
        positive(wall_deadline, 'fault wall deadline')
        if (not isinstance(workloads, dict) or not workloads
                or not isinstance(kubectl_prefix, list) or not 1 <= len(kubectl_prefix) <= 16
                or not all(isinstance(value, str) and 0 < len(value) <= 1024 for value in kubectl_prefix)):
            raise ValueError('Invalid operator fault configuration')
        for role, resource in workloads.items():
            if (not isinstance(role, str) or not NAME.fullmatch(role)
                    or set(resource) != {'namespace', 'kind', 'name', 'uid'}
                    or resource['namespace'] != 'incident-app' or resource['kind'] not in KINDS
                    or not all(isinstance(resource[k], str) and NAME.fullmatch(resource[k]) for k in ('name', 'uid'))):
                raise ValueError('Fault roles require exact operator-observed workload identities')
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.sandbox, self.guard = sandbox, guard
        self.owner_pid = os.getpid()
        self.workloads = copy.deepcopy(workloads)
        self.kubectl_prefix = list(kubectl_prefix)
        self.monotonic_deadline, self.wall_deadline = monotonic_deadline, wall_deadline
        self.monotonic, self.wall = monotonic, wall
        self.operation = operation
        self.revoked = threading.Event()
        atomic_json(self.directory / 'scope.json', {'sandbox': sandbox.name, 'workloads': workloads,
                                                   'kubectl_prefix': kubectl_prefix,
                                                   'wall_deadline': wall_deadline})
        self.check(FAULT_ALLOWANCE)
        self.broker = FaultBroker(workloads, self._fault, idle_seconds=60)

    def check(self, allowance):
        if (self.revoked.is_set() or os.getpid() != self.owner_pid or self.sandbox.stopped
                or self.guard.process.poll() is not None
                or (self.guard.directory / 'release.json').exists()
                or (self.guard.directory / 'result.json').exists()
                or min(self.monotonic_deadline - self.monotonic(),
                       self.wall_deadline - self.wall()) < allowance):
            raise FaultSetupError('Grading fault lifetime unavailable')

    def exec_argv(self, command):
        self.check(COMMAND_ALLOWANCE)
        return self.sandbox.exec_argv(command)

    @contextmanager
    def _fault(self, role):
        self.check(FAULT_ALLOWANCE)
        resource = self.workloads[role]
        with Attempt(self.directory / ('fault-' + uuid.uuid4().hex),
                     {'role': role, 'resource': resource, 'sandbox': self.sandbox.name}) as attempt:
            attempt.transition('preflight')
            result = {'outcome': 'fault_incomplete'}
            def checked_operation(*args, **kwargs):
                self.check(COMMAND_ALLOWANCE)
                report = self.operation(*args, **kwargs)
                observed = report.get('observation', {}).get('workload', {})
                if observed.get('uid') != resource['uid']:
                    raise FaultSetupError('Operator-selected workload identity changed')
                return report
            try:
                with suspended_workload(attempt, self, label='workload', kubectl_prefix=self.kubectl_prefix,
                                        namespace=resource['namespace'], kind=resource['kind'],
                                        name=resource['name'], operation=checked_operation):
                    yield
                result['outcome'] = 'fault_restored'
            except BaseException as error:
                result['error_type'] = type(error).__name__
                raise
            finally:
                attempt.transition('failed')
                attempt.finish(result)

    def close(self):
        # Revoke before closing the endpoint: cleanup threads may no longer start
        # commands once deployment teardown begins. The sandbox is then stopped.
        self.revoked.set()
        self.broker.close()
