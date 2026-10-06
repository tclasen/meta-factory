"""Bind operator fixture callbacks to the existing guarded grading lifetime."""
import math
import json
import os
from pathlib import Path
import time

from .evidence import positive
from .verdicts import Inconclusive
from .preparation import read_regular
from .watchdog import NAME, validate_config


class FixtureLifetime:
    """Read-only checks; an outer owner must still bound callback execution.

    Original adapter attributes can be restored for cleanup after a buggy
    callback. Restoration grants no readiness or ownership of another resource.
    It cannot restart a watchdog or undo a completed sandbox stop.
    """
    def __init__(self, sandbox, guard, *, monotonic_deadline, wall_deadline,
                 monotonic=time.monotonic, wall=time.time):
        for value in (monotonic_deadline, wall_deadline):
            positive(value, 'fixture deadline')
        if not NAME.fullmatch(sandbox.name) or '-grader-' not in sandbox.name:
            raise ValueError('Owned grading sandbox required for fixture preparation')
        self.sandbox, self.guard = sandbox, guard
        self.owner = os.getpid()
        self.monotonic_deadline, self.wall_deadline = monotonic_deadline, wall_deadline
        self.monotonic, self.wall = monotonic, wall
        self.scope = {key: getattr(sandbox, key) for key in ('name', 'project', 'specification')}
        self.creation_attempted = sandbox.creation_attempted
        self.guard_scope = {key: getattr(guard, key) for key in ('directory', 'process', 'nonce')}
        self.config = read_regular(Path(guard.directory) / 'config.json', 65536, lambda: None)
        config = json.loads(self.config)
        validate_config(config)
        if (config['sandbox'] != sandbox.name or config['owner_pid'] != self.owner
                or config['nonce'] != guard.nonce):
            raise ValueError('Fixture watchdog belongs to another deployment')
        self.guard_wall_deadline = config['expires_at']
        self.check()

    def check(self, reserve=0):
        if (type(reserve) not in (int, float) or not math.isfinite(reserve) or reserve < 0):
            raise ValueError('Finite nonnegative fixture reserve required')
        changed = (any(getattr(self.sandbox, key) != value for key, value in self.scope.items())
                   or self.guard.directory != self.guard_scope['directory']
                   or self.guard.process is not self.guard_scope['process']
                   or self.guard.nonce != self.guard_scope['nonce'])
        directory = Path(self.guard_scope['directory'])
        try:
            config_changed = read_regular(directory / 'config.json', 65536, lambda: None) != self.config
        except OSError:
            raise Inconclusive('Fixture watchdog configuration unavailable') from None
        clocks = (self.monotonic(), self.wall())
        if any(type(value) not in (int, float) or not math.isfinite(value) for value in clocks):
            raise Inconclusive('Fixture lifetime clocks unavailable')
        if (os.getpid() != self.owner or changed or config_changed or self.sandbox.stopped
                or self.sandbox.creation_attempted is not True
                or self.guard_scope['process'].poll() is not None
                or (directory / 'release.json').exists() or (directory / 'result.json').exists()
                or min(self.monotonic_deadline - clocks[0], self.wall_deadline - clocks[1],
                       self.guard_wall_deadline - clocks[1]) <= reserve):
            raise Inconclusive('Fixture deployment lifetime unavailable')
        return True

    def restore_scope(self):
        """Keep cleanup pointed at original owned adapters, even on callback error."""
        for key, value in self.scope.items():
            setattr(self.sandbox, key, value)
        self.sandbox.creation_attempted = self.creation_attempted
        for key, value in self.guard_scope.items():
            setattr(self.guard, key, value)
