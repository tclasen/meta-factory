"""Verified worker hold, storage handoff and restart within one fault lifetime."""
from contextlib import contextmanager, ExitStack
import copy
from pathlib import Path
import threading
import uuid

from .evidence import Attempt, atomic_json
from .fault_runtime import FaultRuntime, COMMAND_ALLOWANCE
from .faults import FaultRestoreError, FaultSetupError
from .staging_broker import StagingBroker, WORKER_RECEIPT, STORAGE_RECEIPT, RESTART_RECEIPT, restart_window
from .workload_probe import converged


class StagingRuntime:
    """Attach only to a live parent-owned FaultRuntime with explicit compound opt-in.

    Initial API observations prove workload readiness and HTTP connectivity, not
    successful authenticated enqueue/approval. The protected grader must establish
    those while the worker is held, otherwise staging remains inconclusive.
    The supplied fault runtime must stay alive until this capability has closed.
    """
    def __init__(self, directory, faults):
        if (not isinstance(faults, FaultRuntime) or not faults.storage_worker_restart
                or not {'api', 'worker', 'storage'} <= faults.workloads.keys()
                or not {'api', 'storage'} <= faults.service_probes.keys()):
            raise ValueError('Staging requires exact API/worker/storage and independent service probes')
        resources = faults.workloads
        identities = [(resources[role]['namespace'], resources[role]['kind'], resources[role]['name'])
                      for role in ('api', 'worker', 'storage')]
        if len(set(identities)) != 3 or len({resources[role]['uid'] for role in ('api', 'worker', 'storage')}) != 3:
            raise ValueError('Staging requires three distinct workload identities')
        self.faults = faults
        self.resources = copy.deepcopy(resources)
        self.probes = copy.deepcopy(faults.service_probes)
        self.revoked = threading.Event()
        self.closed = False
        # Reserve both full workload contexts, compound restart and observations.
        # This is a control reserve, never an extension of the grading deadline.
        self.reserve = 2*faults.workload_fault_allowance + faults.fault_allowance + 4*COMMAND_ALLOWANCE
        self.check(self.reserve)
        self.directory = Path(directory); self.directory.mkdir(mode=0o700)
        atomic_json(self.directory/'scope.json', {'sandbox':faults.sandbox.name, 'reserve_seconds':self.reserve})
        self.broker = StagingBroker(self._stage)

    def check(self, allowance):
        if (self.revoked.is_set() or self.faults.workloads != self.resources
                or self.faults.service_probes != self.probes or not self.faults.storage_worker_restart):
            raise FaultSetupError('Staging capability revoked or binding changed')
        self.faults.check(allowance)

    def _observe(self, attempt, role, replicas=None):
        self.check(COMMAND_ALLOWANCE)
        resource = self.resources[role]
        report = self.faults.operation(attempt, self.faults, label='observe-'+role,
            kubectl_prefix=self.faults.kubectl_prefix, namespace=resource['namespace'],
            kind=resource['kind'], name=resource['name'], expected=None, replicas=None)
        self.check(COMMAND_ALLOWANCE)
        observed = report.get('observation',{}).get('workload',{})
        expected = observed.get('replicas') if replicas is None else replicas
        try:
            valid = (report.get('outcome')=='workload_observed' and type(expected) is int
                     and (replicas is not None or expected>0) and converged(observed,resource['uid'],expected))
        except (KeyError,ValueError,TypeError): valid=False
        if not valid: raise FaultRestoreError('Staged workload state changed')
        return observed

    def _service(self, attempt, role, mode):
        self.check(COMMAND_ALLOWANCE)
        report = self.faults.service_runner(attempt,self.faults,label='service-'+role,
                                           configuration=self.probes[role],mode=mode)
        self.check(COMMAND_ALLOWANCE)
        if report.get('outcome')!='service_'+mode+'_verified':
            raise FaultRestoreError('Independent staged service state changed')

    @contextmanager
    def _stage(self):
        self.check(self.reserve)
        with Attempt(self.directory/('stage-'+uuid.uuid4().hex),
                     {'sandbox':self.faults.sandbox.name,'operation':'job_staging'}) as attempt:
            attempt.transition('preflight');result={'outcome':'staging_incomplete'}
            try:
                api = self._observe(attempt,'api')
                worker = self._observe(attempt,'worker')
                with ExitStack() as cleanup:
                    # On a partial handoff failure, restore storage before worker.
                    # After a successful handoff the worker stack is already empty.
                    worker_stack = cleanup.enter_context(ExitStack())
                    storage_stack = cleanup.enter_context(ExitStack())
                    observation = worker_stack.enter_context(self.faults._fault('worker'))
                    if observation.get('workload_suspended_verified') is not True:
                        raise FaultSetupError('Initial staged worker hold unavailable')
                    handle = StagingHandle(self,worker_stack,storage_stack,api['replicas'],worker['replicas'])
                    handle.observations = handle.verify()
                    yield handle
                result['outcome']='staging_restored'
            except BaseException as error:
                result['error_type']=type(error).__name__;raise
            finally:
                attempt.transition('failed');attempt.finish(result)

    def close(self):
        # Revoke new staging actions while existing owned fault contexts unwind
        # under the still-active parent fault runtime and outer guard.
        if self.closed: return
        self.revoked.set();self.broker.close();self.closed=True


class StagingHandle:
    def __init__(self,runtime,worker_stack,storage_stack,api_replicas,worker_replicas):
        self.runtime,self.worker_stack,self.storage_stack=runtime,worker_stack,storage_stack
        self.api_replicas,self.worker_replicas=api_replicas,worker_replicas
        self.handed_off=False;self.restarted=False
        self.observations={}

    def verify(self):
        runtime=self.runtime;runtime.check(3*COMMAND_ALLOWANCE)
        with Attempt(runtime.directory/('verify-'+uuid.uuid4().hex),
                     {'operation':'storage_hold' if self.handed_off else 'worker_hold'}) as attempt:
            attempt.transition('preflight');result={'outcome':'staging_check_incomplete'}
            try:
                if self.handed_off:
                    runtime._observe(attempt,'storage',0)
                    runtime._observe(attempt,'worker',self.worker_replicas)
                    runtime._service(attempt,'storage','unavailable')
                    fields=STORAGE_RECEIPT
                else:
                    runtime._observe(attempt,'worker',0)
                    runtime._observe(attempt,'api',self.api_replicas)
                    runtime._service(attempt,'api','available')
                    fields=WORKER_RECEIPT
                result['outcome']='staging_hold_verified'
                return {field:True for field in fields}
            except BaseException as error:
                result['error_type']=type(error).__name__;raise
            finally:
                attempt.transition('failed');attempt.finish(result)

    def handoff(self):
        if self.handed_off:raise FaultSetupError('Staging handoff already performed')
        runtime=self.runtime
        runtime.check(runtime.faults.fault_allowance + 4*COMMAND_ALLOWANCE)
        self.verify()
        storage = self.storage_stack.enter_context(runtime.faults._fault('storage'))
        if (storage.get('workload_suspended_verified') is not True
                or storage.get('service_outage_verified') is not True):
            raise FaultSetupError('Staged storage outage unavailable')
        # A released worker may immediately claim queued work. Storage has already
        # been independently proved unavailable, preventing fast publication.
        self.worker_stack.close()
        self.handed_off=True
        return self.verify()

    def restart_worker(self):
        if not self.handed_off or self.restarted:
            raise FaultSetupError('Staged restart requires a single completed handoff')
        self.restarted=True
        self.verify()
        result=self.runtime.faults._restart_worker_under_storage()
        if (result.get('held_fault_verified') is not True
                or result.get('workload_restarted_verified') is not True):
            raise FaultRestoreError('Staged worker restart not verified')
        self.verify()
        return dict({field:True for field in RESTART_RECEIPT},
                    restart_window=restart_window(result.get('restart_window')))
