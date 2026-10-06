"""Bind protected repeat bootstrap to fresh deployment and one case deadline."""
import copy
import os
from pathlib import Path
import threading
import time
import uuid

from .bootstrap import repeat_bootstrap
from .evidence import Attempt, positive
from .ops_broker import OpsBroker
from .sandbox import disjoint
from .verdicts import Inconclusive
from .watchdog import NAME


class OpsRuntime:
    """Trusted callbacks must honor deadlines; close cannot interrupt Python code."""
    def __init__(self, directory, sandbox, guard, *, observe, verify, expected_case,
                 source_check, monotonic_deadline, wall_deadline, timeout=1800,
                 operation=repeat_bootstrap):
        for value in (monotonic_deadline, wall_deadline, timeout):
            positive(value, 'operations bound')
        if (not all(callable(value) for value in (observe, verify, source_check, operation))
                or not isinstance(expected_case, dict) or not expected_case
                or not NAME.fullmatch(sandbox.name) or '-grader-' not in sandbox.name):
            raise ValueError('Independent operations binding required')
        self.directory = Path(directory)
        for mount in (sandbox.project, sandbox.specification):
            disjoint(self.directory, mount)
        self.sandbox, self.guard = sandbox, guard
        self.owner = os.getpid()
        self.identity = (sandbox.name, str(sandbox.project))
        self.revoked = threading.Event()
        self.monotonic_deadline, self.wall_deadline = monotonic_deadline, wall_deadline
        self.case_deadlines = None
        self.timeout, self.operation = timeout, operation
        self.options = dict(observe=observe, verify=verify,
                            expected_case=copy.deepcopy(expected_case), source_check=self.checked_source)
        self.source_check = source_check
        self.check()
        self.directory.mkdir(mode=0o700)
        self.broker = OpsBroker(self.execute, bind_case=self.bind, settle_check=self.check)

    def check(self):
        deadlines = self.case_deadlines or (self.monotonic_deadline, self.wall_deadline)
        if (self.revoked.is_set() or os.getpid()!=self.owner
                or (self.sandbox.name,str(self.sandbox.project))!=self.identity
                or self.sandbox.stopped or not self.sandbox.creation_attempted
                or self.guard.process.poll() is not None
                or (self.guard.directory/'release.json').exists()
                or (self.guard.directory/'result.json').exists()
                or min(deadlines[0]-time.monotonic(), deadlines[1]-time.time())<=0):
            raise Inconclusive('Operations deployment lifetime unavailable')

    def bind(self, case_id, *, timeout_seconds):
        self.check()
        if self.case_deadlines is not None:raise ValueError('Operations already bound')
        self.case_deadlines = (min(self.monotonic_deadline,time.monotonic()+timeout_seconds),
                               min(self.wall_deadline,time.time()+timeout_seconds))
        self.check()

    def checked_source(self, reserve):
        self.check()
        value = self.source_check(reserve)
        self.check()
        return value

    def execute(self):
        self.check()
        if self.case_deadlines is None:raise Inconclusive('Operations case unavailable')
        with Attempt(self.directory/('repeat-'+uuid.uuid4().hex), {'sandbox':self.identity[0]}) as attempt:
            attempt.transition('preflight')
            result = dict(outcome='repeat_bootstrap_incomplete', verdict='inconclusive', abort_suite=True)
            try:
                result = self.operation(attempt,self.sandbox,self.guard,
                    monotonic_deadline=self.case_deadlines[0], wall_deadline=self.case_deadlines[1],
                    timeout=self.timeout, **self.options)
                self.check()
                return result
            except BaseException:
                result = dict(outcome='repeat_bootstrap_incomplete', verdict='inconclusive', abort_suite=True)
                raise
            finally:
                attempt.transition('failed')
                attempt.finish(result)

    def close(self):
        self.revoked.set()
        self.broker.close()
