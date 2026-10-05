"""Bind browser execution to post-bootstrap fixtures and the outer sbx guard."""

import copy
import os
import re
import threading
import time

from .browser import BrowserFixtureUnavailable
from .browser_runtime import BrowserExecutor
from .evidence import positive


class BrowserBinding:
    def __init__(self, sandbox, guard, configuration, *, base_url, monotonic_deadline, wall_deadline,
                 executor_factory=BrowserExecutor, monotonic=time.monotonic, wall=time.time):
        positive(monotonic_deadline, 'browser grading deadline')
        positive(wall_deadline, 'browser grading wall deadline')
        required = {'image', 'seccomp', 'seccomp_sha256', 'network', 'peer_host', 'peer_port', 'peer_check', 'fixtures'}
        if (not isinstance(configuration, dict) or set(configuration) != required
                or not callable(configuration['peer_check']) or not isinstance(configuration['fixtures'], dict)
                or not re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}', base_url)):
            raise ValueError('Incomplete post-bootstrap browser configuration')
        self.fixtures = copy.deepcopy(configuration['fixtures'])
        for identifier, fixture in self.fixtures.items():
            if (not isinstance(identifier, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,57}', identifier)
                    or not isinstance(fixture, dict) or any(not isinstance(key, str) for key in fixture)
                    or {'base_url', '_fault_control', '_audit_control', '_job_control'} & fixture.keys()):
                raise ValueError('Invalid browser fixture binding')
        self.base_url = base_url
        self.sandbox, self.guard = sandbox, guard
        self.owner_pid = os.getpid()
        self.monotonic_deadline, self.wall_deadline = monotonic_deadline, wall_deadline
        self.monotonic, self.wall = monotonic, wall
        self.revoked = threading.Event()
        self.peer_check = configuration['peer_check']
        self.check(1)
        options = {key: value for key, value in configuration.items() if key not in ('peer_check', 'fixtures')}
        self.executor = executor_factory(**options, peer_check=self.checked_peer)

    def check(self, allowance):
        if (self.revoked.is_set() or os.getpid() != self.owner_pid or self.sandbox.stopped
                or self.guard.process.poll() is not None
                or (self.guard.directory / 'release.json').exists()
                or (self.guard.directory / 'result.json').exists()
                or min(self.monotonic_deadline - self.monotonic(), self.wall_deadline - self.wall()) <= allowance):
            raise RuntimeError('Outer browser deployment lifetime unavailable')

    def checked_peer(self):
        self.check(1)
        # Resolvers must implement this explicit one-second identity-check budget.
        self.peer_check(1)
        self.check(0)

    def __call__(self, attempt, suite, case, target, *, timeout_seconds):
        self.check(0)
        if target.get('base_url') != self.base_url:
            raise ValueError('Browser deployment endpoint changed')
        if case['id'] not in self.fixtures:
            raise BrowserFixtureUnavailable('Operator browser fixture not bound')
        remaining = min(timeout_seconds, self.monotonic_deadline - self.monotonic(),
                        self.wall_deadline - self.wall())
        if remaining <= 135:
            raise BrowserFixtureUnavailable('Browser budget cannot cover cleanup')
        # Fixture IDs and control labels come from the trusted post-bootstrap
        # resolver; neither can replace the outer deployment endpoint/capabilities.
        selected = dict(target, **copy.deepcopy(self.fixtures[case['id']]))
        selected.pop('_audit_control', None)
        selected.pop('_fault_control', None)
        selected.pop('_job_control', None)
        value = self.executor(attempt, suite, case, selected, timeout_seconds=remaining)
        self.check(0)
        return value

    def close(self):
        self.revoked.set()
