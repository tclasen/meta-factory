"""Guard lifetime and private evidence around fixed parent security inspections."""
import os
from pathlib import Path
import threading
import time
import uuid

from .evidence import Attempt,atomic_json,positive
from .security_broker import OPERATIONS,SecurityBroker,SecurityObservationError,project,request_values


INSPECTION_TIMEOUT=30
INSPECTION_RESERVE=40


class SecurityRuntime:
    """inspections maps fixed operation names to independently bound readers.

    Each reader(canaries, timeout=...) must enforce command/time/source bounds and
    return a sanitized verdict. Password canaries are always None; its immutable
    account/profile scope stays parent-side. Log source inventory/history remains
    parent-side; missing coverage cannot produce a pass. log_binary_canaries
    readers receive known bytes; log_canaries readers receive known strings.
    peer_check(operation, timeout=...) must return exactly True for the independently bound active peer.
    No reader, source, profile or command is selected by builder/worker output.
    """
    def __init__(self,directory,sandbox,guard,*,inspections,peer_check,monotonic_deadline,
                 wall_deadline,monotonic=time.monotonic,wall=time.time):
        positive(monotonic_deadline,'security monotonic deadline')
        positive(wall_deadline,'security wall deadline')
        if (not isinstance(inspections,dict) or not inspections or not set(inspections)<=OPERATIONS
                or any(not callable(value) for value in inspections.values()) or not callable(peer_check)):
            raise ValueError('Fixed trusted security inspections and peer check required')
        self.inspections=dict(inspections);self.peer_check=peer_check
        self.sandbox,self.guard=sandbox,guard;self.owner_pid=os.getpid()
        self.monotonic_deadline,self.wall_deadline=monotonic_deadline,wall_deadline
        self.monotonic,self.wall=monotonic,wall;self.revoked=threading.Event()
        self.check(INSPECTION_RESERVE)
        self.directory=Path(directory);self.directory.mkdir(mode=0o700)
        atomic_json(self.directory/'scope.json',dict(sandbox=sandbox.name,wall_deadline=wall_deadline,operations=sorted(inspections)))
        self.broker=SecurityBroker(self._inspect)

    def check(self,allowance):
        if (self.revoked.is_set() or os.getpid()!=self.owner_pid or self.sandbox.stopped
                or self.guard.process.poll() is not None
                or (self.guard.directory/'release.json').exists() or (self.guard.directory/'result.json').exists()
                or min(self.monotonic_deadline-self.monotonic(),self.wall_deadline-self.wall())<allowance):
            raise SecurityObservationError('Security inspection lifetime unavailable')

    def checked_peer(self,operation,allowance):
        self.check(allowance)
        if self.peer_check(operation,timeout=1) is not True:
            raise SecurityObservationError('Security inspection peer unavailable')
        self.check(allowance)

    def _inspect(self,operation,canaries):
        request_values(operation,canaries)
        if operation not in self.inspections:raise SecurityObservationError('Security inspection not granted')
        self.checked_peer(operation,INSPECTION_RESERVE)
        with Attempt(self.directory/('inspect-'+uuid.uuid4().hex),{'sandbox':self.sandbox.name,'operation':operation}) as attempt:
            attempt.transition('preflight');result=dict(outcome='security_inspection_incomplete')
            try:
                value=self.inspections[operation](canaries,timeout=INSPECTION_TIMEOUT)
                self.checked_peer(operation,5)
                receipt=project(operation,value)
                result.update(outcome='security_observed',verdict=receipt['verdict'])
                return receipt
            except BaseException as error:
                result['error_type']=type(error).__name__;raise
            finally:
                # Fixed enum/error type only; callback values/requests remain private.
                attempt.transition('failed');attempt.finish(result)

    def close(self):
        self.revoked.set();self.broker.close()
