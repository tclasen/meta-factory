"""Parent-owned duration bounds for unchanged running API/worker container sets."""
import copy
import math
import re
import time

from .faults import FaultSetupError
from .workload_probe import NAME, converged


class RunningClock:
    """Trusted callbacks must enforce guard/owner/deadline and command bounds.

    earliest brackets possible worker restoration, not an application timestamp.
    Unchanged Kubernetes instance/restart fingerprints establish continuity only
    within the reviewed operator envelope: no external process/container pauses.
    This is not proof of CPU scheduling, useful queue progress or retry start.
    """
    def __init__(self, resources, observe, check, *, earliest, monotonic=time.monotonic):
        if (not isinstance(resources, dict) or set(resources) != {'api', 'worker'}
                or not callable(observe) or not callable(check) or not callable(monotonic)):
            raise ValueError('Trusted running clock bindings required')
        for resource in resources.values():
            if (not isinstance(resource, dict) or set(resource) != {'namespace', 'kind', 'name', 'uid'}
                    or any(not isinstance(value, str) or not NAME.fullmatch(value) for value in resource.values())):
                raise ValueError('Exact running workload identities required')
        if resources['api']['uid'] == resources['worker']['uid']:
            raise ValueError('Running clock requires distinct workloads')
        self.resources = copy.deepcopy(resources)
        self.observe, self.check, self.monotonic = observe, check, monotonic
        self.invalid = False;self.identities = None;self.initial_latest = None
        self.last = self._finite(earliest);self.earliest = self.last
        self._clock()

    @staticmethod
    def _finite(value):
        try:
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
        except OverflowError:valid = False
        if not valid:raise FaultSetupError('Running clock time unavailable')
        return value

    def _clock(self):
        value = self._finite(self.monotonic())
        if value < self.last:raise FaultSetupError('Running clock moved backwards')
        self.last = value
        return value

    def invalidate(self):
        self.invalid = True

    def _identity(self, role, snapshot):
        resource = self.resources[role]
        try:
            replicas = snapshot['replicas']
            if (any(snapshot[key] != value for key, value in resource.items())
                    or type(replicas) is not int or not 1 <= replicas <= 100
                    or any(type(snapshot[key]) is not int or snapshot[key] < 0
                           for key in ('generation', 'observed_generation'))
                    or not converged(snapshot, resource['uid'], replicas, convergence='running')):
                raise ValueError('Workload not running')
            pods = []
            for pod in snapshot['pods']:
                if (any(not isinstance(pod.get(key), str) or not NAME.fullmatch(pod[key])
                        for key in ('name', 'uid'))
                        or not isinstance(pod.get('process_fingerprint'), str)
                        or not re.fullmatch('[0-9a-f]{64}', pod['process_fingerprint'])):
                    raise ValueError('Instance continuity unavailable')
                pods.append((pod['uid'], pod['name'], pod['process_fingerprint']))
            if len({p[0] for p in pods}) != replicas or len({p[1] for p in pods}) != replicas:
                raise ValueError('Ambiguous Pod identity')
            return (resource['uid'], snapshot['generation'], replicas, tuple(sorted(pods)))
        except (KeyError, TypeError, ValueError):
            raise FaultSetupError('Running workload continuity unavailable') from None

    def sample(self):
        if self.invalid:raise FaultSetupError('Running clock was invalidated')
        try:
            identities = {};starts = [];ends = []
            for role in ('api', 'worker'):
                self.check();starts.append(self._clock())
                snapshot = self.observe(role)
                ends.append(self._clock());self.check()
                identities[role] = self._identity(role, snapshot)
            if self.identities is None:
                self.identities = identities;self.initial_latest = max(ends)
            elif identities != self.identities:
                raise FaultSetupError('Running workload instance or generation changed')
            # The intersection of independently observed role intervals supplies
            # the lower bound. The possible handoff interval supplies the upper.
            return {'minimum': max(0, min(starts) - self.initial_latest),
                    'maximum': self._clock() - self.earliest}
        except Exception:
            self.invalid = True
            raise FaultSetupError('Independent running-service clock unavailable') from None
