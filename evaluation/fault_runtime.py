"""Bind parent-owned fault requests to one guarded grading sandbox."""

from contextlib import contextmanager, nullcontext
import copy
import os
from pathlib import Path
import threading
import time
import uuid

from .evidence import Attempt, atomic_json, positive
from .fault_broker import FaultBroker
from .faults import FaultRestoreError, FaultSetupError, suspended_workload
from .workload_probe import KINDS, NAME, converged
from .workloads import workload_operation
from .services import service_operation
from .audit_faults import audit_insert_failure, FAULT_RESERVE
from .database_transport import DatabaseTransport
from .job_broker import export_identity


COMMAND_ALLOWANCE = 150  # 135-second command ceiling plus scheduling allowance.
FAULT_ALLOWANCE = 630    # Four commands, 60-second body, plus scheduling allowance.
RESTORATION_OBSERVER_ALLOWANCE = 60


class FaultRuntime:
    def __init__(self, directory, sandbox, guard, workloads, kubectl_prefix, *,
                 monotonic_deadline, wall_deadline, operation=workload_operation,
                 monotonic=time.monotonic, wall=time.time, service_probes=None, service_runner=service_operation,
                 audit_binding=None, database_peer=None, database_peer_check=None,
                 storage_worker_restart=False, worker_restart_context=None,
                 restoration_observers=None):
        positive(monotonic_deadline, 'fault monotonic deadline')
        positive(wall_deadline, 'fault wall deadline')
        audit_enabled = audit_binding is not None
        if audit_enabled:
            if (not isinstance(audit_binding, dict) or not isinstance(database_peer, dict)
                    or set(database_peer) != {'prefix', 'services', 'cwd'}
                    or not callable(database_peer_check)):
                raise ValueError('Audit faults require an operator binding and verified database peer')
        elif database_peer is not None or database_peer_check is not None:
            raise ValueError('Database peer requires an audit binding')
        if (not isinstance(workloads, dict) or not (workloads or audit_enabled)
                or not isinstance(kubectl_prefix, list) or not 1 <= len(kubectl_prefix) <= 16
                or not all(isinstance(value, str) and 0 < len(value) <= 1024 for value in kubectl_prefix)):
            raise ValueError('Invalid operator fault configuration')
        if audit_enabled and 'audit' in workloads:
            raise ValueError('Audit role cannot also suspend a workload')
        for role, resource in workloads.items():
            if (not isinstance(role, str) or not NAME.fullmatch(role)
                    or set(resource) != {'namespace', 'kind', 'name', 'uid'}
                    or resource['namespace'] != 'incident-app' or resource['kind'] not in KINDS
                    or not all(isinstance(resource[k], str) and NAME.fullmatch(resource[k]) for k in ('name', 'uid'))):
                raise ValueError('Fault roles require exact operator-observed workload identities')
        service_probes = {} if service_probes is None else service_probes
        if not isinstance(service_probes, dict) or not set(service_probes) <= set(workloads):
            raise ValueError('Service probes must belong to reviewed fault roles')
        restoration_observers = {} if restoration_observers is None else restoration_observers
        if (not isinstance(restoration_observers, dict)
                or not set(restoration_observers) <= set(service_probes)
                or any(not callable(observer) for observer in restoration_observers.values())):
            raise ValueError('Restoration observers require trusted callbacks and independent service probes')
        if type(storage_worker_restart) is not bool:
            raise ValueError('Compound restart selection must be a boolean')
        if worker_restart_context is not None and (
                not callable(worker_restart_context) or not storage_worker_restart):
            raise ValueError('Worker restart context requires compound restart and a trusted factory')
        if storage_worker_restart:
            if not {'storage', 'worker'} <= workloads.keys() or 'storage' not in service_probes:
                raise ValueError('Compound restart requires independently mapped storage/worker and storage probe')
            left, right = workloads['storage'], workloads['worker']
            if left['uid'] == right['uid'] or all(left[k] == right[k] for k in ('namespace', 'kind', 'name')):
                raise ValueError('Compound restart requires distinct workload identities')
        self.storage_worker_restart = storage_worker_restart
        self.worker_restart_context = worker_restart_context
        self.held_workloads = {}
        self.mutation_lock = threading.RLock()
        self.service_probes = copy.deepcopy(service_probes)
        self.restoration_observers = dict(restoration_observers)
        self.service_runner = service_runner
        self.fault_allowance = (FAULT_ALLOWANCE + (120 if service_probes else 0)) if workloads else FAULT_RESERVE
        if restoration_observers:
            self.fault_allowance += RESTORATION_OBSERVER_ALLOWANCE
        self.workload_fault_allowance = self.fault_allowance
        if storage_worker_restart:
            self.fault_allowance = 2 * self.workload_fault_allowance + 6 * COMMAND_ALLOWANCE
        self.audit_binding = copy.deepcopy(audit_binding)
        self.database_peer = copy.deepcopy(database_peer)
        self.database_peer_check = database_peer_check
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
                                                   'wall_deadline': wall_deadline, 'service_probes': service_probes,
                                                   'audit_enabled': audit_enabled,
                                                   'restoration_observer_roles': sorted(restoration_observers),
                                                   'storage_worker_restart': storage_worker_restart})
        self.check(self.fault_allowance)
        actions = {('storage', 'worker'): self._restart_worker_under_storage} if storage_worker_restart else {}
        self.broker = FaultBroker([*workloads, *(['audit'] if audit_enabled else [])], self._fault,
                                  idle_seconds=60, restart_actions=actions)

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
        # Different broker threads cannot mutate the same deployment concurrently.
        # Nested owned contexts in one staging thread remain permitted.
        if not self.mutation_lock.acquire(blocking=False):
            raise FaultSetupError('Another parent fault lifetime is active')
        try:
            with self._owned_fault(role) as observation:
                yield observation
        finally:
            self.mutation_lock.release()

    @contextmanager
    def _owned_fault(self, role):
        if role == 'audit' and self.audit_binding is not None:
            with self._audit_fault() as observation:
                yield observation
            return
        self.check(self.fault_allowance if role == 'storage' and self.storage_worker_restart
                   else self.workload_fault_allowance)
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
            def verify_service(phase, mode):
                self.check(COMMAND_ALLOWANCE)
                report = self.service_runner(attempt, self, label='service-' + phase,
                                             configuration=self.service_probes[role], mode=mode)
                if report.get('outcome') != 'service_' + mode + '_verified':
                    error = FaultRestoreError if phase == 'recovery' else FaultSetupError
                    raise error('Independent service observation incomplete: ' + phase)
            def worker_convergence():
                return ('running' if role == 'worker' and self.storage_worker_restart
                        and 'storage' in self.held_workloads else 'ready')
            try:
                if role in self.service_probes:
                    verify_service('baseline', 'available')
                with suspended_workload(attempt, self, label='workload', kubectl_prefix=self.kubectl_prefix,
                                        namespace=resource['namespace'], kind=resource['kind'],
                                        name=resource['name'], operation=checked_operation,
                                        convergence=worker_convergence(), restore_convergence=worker_convergence) as suspended:
                    self.held_workloads[role] = copy.deepcopy(suspended)
                    try:
                        if role in self.service_probes:
                            verify_service('outage', 'unavailable')
                        yield {'service_outage_verified': role in self.service_probes,
                               'workload_suspended_verified': True}
                    finally:
                        self.held_workloads.pop(role, None)
                if role in self.service_probes:
                    verify_service('recovery', 'available')
                observer = self.restoration_observers.get(role)
                if observer is not None:
                    self.check(RESTORATION_OBSERVER_ALLOWANCE)
                    receipt = {'role': role, 'resource': copy.deepcopy(resource),
                               'workload_restored_verified': True,
                               'service_recovered_verified': True}
                    atomic_json(attempt.directory / 'restoration-observer-input.json', receipt)
                    started, wall_started = self.monotonic(), self.wall()
                    verified = observer(resource=copy.deepcopy(resource), evidence_directory=attempt.directory)
                    elapsed, wall_elapsed = self.monotonic() - started, self.wall() - wall_started
                    self.check(0)
                    if (verified is not True or not 0 <= elapsed < RESTORATION_OBSERVER_ALLOWANCE
                            or not 0 <= wall_elapsed < RESTORATION_OBSERVER_ALLOWANCE):
                        raise FaultRestoreError('Restored peer observation incomplete or late')
                    atomic_json(attempt.directory / 'restoration-observer-result.json',
                                {'outcome': 'restored_peer_verified', 'elapsed_seconds': elapsed})
                result['outcome'] = 'fault_restored'
            except BaseException as error:
                result['error_type'] = type(error).__name__
                raise
            finally:
                attempt.transition('failed')
                attempt.finish(result)

    def _restart_worker_under_storage(self, *, paused_reader=None, export_id=None):
        if paused_reader is not None and not callable(paused_reader):
            raise ValueError('Trusted paused-worker reader required')
        if export_id is not None:
            export_identity(export_id)
            if paused_reader is None:
                raise ValueError('Export-specific interruption requires a paused job reader')
        if not self.storage_worker_restart or 'storage' not in self.held_workloads:
            raise FaultSetupError('Reviewed storage hold is not active')
        paused_reserve = 3 * COMMAND_ALLOWANCE + 25 if paused_reader is not None else 0
        self.check(self.workload_fault_allowance + 6 * COMMAND_ALLOWANCE + 120 + paused_reserve)
        resource = self.workloads['storage']
        with Attempt(self.directory / ('restart-' + uuid.uuid4().hex),
                     {'held_role': 'storage', 'restart_role': 'worker', 'sandbox': self.sandbox.name}) as attempt:
            attempt.transition('preflight')
            result = {'outcome': 'held_restart_incomplete'}
            def held(phase):
                self.check(COMMAND_ALLOWANCE)
                report = self.operation(attempt, self, label='held-' + phase,
                    kubectl_prefix=self.kubectl_prefix, namespace=resource['namespace'],
                    kind=resource['kind'], name=resource['name'], expected=None, replicas=None)
                observed = report.get('observation', {}).get('workload', {})
                try:
                    verified = (report.get('outcome') == 'workload_observed' and converged(observed, resource['uid'], 0)
                                and observed.get('generation') == self.held_workloads['storage'].get('generation'))
                except (KeyError, TypeError, ValueError):
                    verified = False
                if not verified:
                    raise FaultRestoreError('Storage hold changed during worker restart')
                self.check(COMMAND_ALLOWANCE)
                service = self.service_runner(attempt, self, label='held-service-' + phase,
                    configuration=self.service_probes['storage'], mode='unavailable')
                if service.get('outcome') != 'service_unavailable_verified':
                    raise FaultRestoreError('Storage outage changed during worker restart')
            try:
                held('before')
                restart_earliest = self.monotonic()
                paused = None
                # Only the parent-selected handler receives the requested identity.
                # Its lifetime includes restoration and the independent paused read.
                context = (self.worker_restart_context(export_id)
                           if export_id is not None and self.worker_restart_context is not None
                           else nullcontext())
                with context, self._fault('worker') as observation:
                    if observation.get('workload_suspended_verified') is not True:
                        raise FaultSetupError('Worker suspension was not verified')
                    if paused_reader is not None:
                        self.check(COMMAND_ALLOWANCE)
                        paused = paused_reader()
                        self.check(COMMAND_ALLOWANCE)
                        worker = self.workloads['worker']
                        report = self.operation(attempt, self, label='paused-worker-check',
                            kubectl_prefix=self.kubectl_prefix, namespace=worker['namespace'],
                            kind=worker['kind'], name=worker['name'], expected=None, replicas=None)
                        observed = report.get('observation', {}).get('workload', {})
                        try:
                            unchanged = (report.get('outcome') == 'workload_observed'
                                and converged(observed, worker['uid'], 0)
                                and observed.get('generation') == self.held_workloads['worker'].get('generation'))
                        except (KeyError, TypeError, ValueError):unchanged = False
                        if not unchanged:raise FaultRestoreError('Worker hold changed during paused job read')
                        held('paused')
                restart_latest = self.monotonic()
                held('after')
                self.check(COMMAND_ALLOWANCE)
                result['outcome'] = 'held_restart_verified'
                result['restart_window'] = {'earliest': restart_earliest, 'latest': restart_latest}
                receipt = {'workload_restarted_verified': True, 'held_fault_verified': True,
                           'restart_window': dict(result['restart_window'])}
                if paused_reader is not None:receipt['paused_job'] = paused
                return receipt
            except BaseException as error:
                result['error_type'] = type(error).__name__
                raise
            finally:
                attempt.transition('failed')
                attempt.finish(result)

    @contextmanager
    def _audit_fault(self):
        def check(allowance):
            self.check(allowance)
            self.database_peer_check(allowance)
            # A peer check may consume time or observe an intervening revocation.
            self.check(allowance)
        check(FAULT_RESERVE)
        with Attempt(self.directory / ('fault-' + uuid.uuid4().hex),
                     {'role': 'audit', 'sandbox': self.sandbox.name}) as attempt:
            attempt.transition('preflight')
            result = {'outcome': 'fault_incomplete'}
            try:
                peer = self.database_peer
                transport = DatabaseTransport(attempt, peer['prefix'], peer['services'],
                                              check=check, cwd=peer['cwd'])
                with audit_insert_failure(attempt, self.audit_binding, execute=transport, check=check) as observation:
                    yield observation
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
