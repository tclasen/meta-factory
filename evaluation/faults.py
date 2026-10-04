"""Scoped workload fault lifetime with durable restoration outcomes."""

from contextlib import contextmanager

from .evidence import atomic_json
from .workload_probe import NAME, converged
from .workloads import workload_operation


class FaultSetupError(RuntimeError):
    """A fault precondition could not be established."""


class FaultRestoreError(RuntimeError):
    """The grading environment cannot safely serve another test."""


@contextmanager
def suspended_workload(attempt, sandbox, *, label, kubectl_prefix, namespace, kind,
                       name, operation=workload_operation):
    """Suspend one selected workload and verify restoration on every exit path.

    This must run under the disposable sandbox's lifetime guard. Process death
    cannot execute finally; the parent grader must abort a timed-out mutating case
    and stop the sandbox. Never use this to mutate a shared production cluster.
    """
    if not isinstance(label, str) or len(label) > 20 or not NAME.fullmatch(label):
        raise ValueError('Invalid fault label')

    def run(phase, expected=None, replicas=None):
        report = operation(attempt, sandbox, label=label + '-' + phase,
                           kubectl_prefix=kubectl_prefix, namespace=namespace, kind=kind,
                           name=name, expected=expected, replicas=replicas)
        wanted = 'workload_observed' if expected is None else 'workload_scaled'
        if report.get('outcome') != wanted:
            raise FaultSetupError('Workload operation incomplete: ' + phase)
        return report['observation']['workload']

    original = run('baseline')
    if original['replicas'] <= 0 or not converged(original, original['uid'], original['replicas']):
        raise FaultSetupError('Selected workload is not running and ready')
    atomic_json(attempt.directory / (label + '-restoration-plan.json'), original)
    result = {'restoration_verified': False, 'uid': original['uid'],
              'original_replicas': original['replicas'], 'fault_established': False}
    try:
        suspended = run('suspend', original, 0)
        if not converged(suspended, original['uid'], 0):
            raise FaultSetupError('Workload suspension was not observed')
        result['fault_established'] = True
        yield suspended
    except BaseException as error:
        result['body_error_type'] = type(error).__name__
        raise
    finally:
        try:
            current = run('before-restore')
            if current['uid'] != original['uid'] or current['replicas'] not in (0, original['replicas']):
                raise FaultRestoreError('Selected workload changed independently')
            restored = run('restore', current, original['replicas'])
            if not converged(restored, original['uid'], original['replicas']):
                raise FaultRestoreError('Restored workload is not ready')
            result['restoration_verified'] = True
        except BaseException as error:
            result['restore_error_type'] = type(error).__name__
            raise FaultRestoreError('Scoped workload restoration incomplete; abort grading') from error
        finally:
            atomic_json(attempt.directory / (label + '-result.json'), result)
