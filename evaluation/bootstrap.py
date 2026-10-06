"""Guarded repeat bootstrap inside one owned grading sandbox, never on the host."""
import copy
import os
from pathlib import Path
import time

from .evidence import atomic_json, collect, positive
from .verdicts import Inconclusive
from .watchdog import NAME


def repeat_bootstrap(attempt, sandbox, guard, *, observe, verify, expected_case,
                     source_check, monotonic_deadline, wall_deadline,
                     timeout=1800, command_runner=collect):
    """Trusted bounded callbacks observe/verify independent fixture preservation.

    Intended for post-bootstrap operator preparation or a future protected ops
    broker. Callbacks must honor the supplied deadline; arbitrary callbacks are
    not interrupted here. The outer owner remains responsible for sandbox cleanup.
    Nonpass requires aborting further grading on this shared deployment. No suite
    acceptance, alternate seed execution or source mapping is implied by this hook.
    """
    positive(timeout, 'repeat bootstrap timeout')
    positive(monotonic_deadline, 'repeat bootstrap monotonic deadline')
    positive(wall_deadline, 'repeat bootstrap wall deadline')
    if (not all(callable(value) for value in (observe, verify, source_check))
            or not isinstance(expected_case, dict) or not expected_case
            or not NAME.fullmatch(sandbox.name) or '-grader-' not in sandbox.name):
        raise ValueError('Independent repeat bootstrap configuration required')
    owner = os.getpid()
    identity = (sandbox.name, str(sandbox.project))
    report = dict(outcome='repeat_bootstrap_incomplete', verdict='inconclusive', abort_suite=True)
    command = None
    stage = 'precondition'
    expected_case = copy.deepcopy(expected_case)
    def check(reserve):
        def live():
            remaining = min(monotonic_deadline-time.monotonic(), wall_deadline-time.time())
            if (os.getpid()!=owner or (sandbox.name,str(sandbox.project))!=identity
                    or sandbox.stopped or not sandbox.creation_attempted
                    or guard.process.poll() is not None
                    or (guard.directory/'release.json').exists()
                    or (guard.directory/'result.json').exists() or remaining<=reserve):
                raise Inconclusive('Repeat bootstrap deployment lifetime unavailable')
            return remaining
        live()
        try:
            if source_check(reserve) is not True:
                raise ValueError()
        except Exception:
            raise Inconclusive('Independent captured source check unavailable') from None
        return live()
    try:
        check(1)
        before = copy.deepcopy(observe(sandbox, monotonic_deadline=monotonic_deadline,
                                       wall_deadline=wall_deadline))
        check(1)
        if verify(before, before, expected_case) is not None:
            raise Inconclusive('Independent bootstrap verifier returned an unsupported result')
        allowance = min(timeout, check(1)-1)
        argv = sandbox.exec_argv(['./ops/bootstrap.sh'])
        expected = ['sbx','exec','-w',identity[1],identity[0],'./ops/bootstrap.sh']
        if argv != expected:
            raise Inconclusive('Repeat bootstrap command escaped the owned sandbox')
        stage = 'command'
        command = command_runner(attempt, 'repeat-bootstrap', argv,
            cwd=Path(__file__).resolve().parents[1], timeout=allowance)
        check(1)
        if command.get('outcome') == 'passed' and (type(command.get('exit_code')) is not int or command['exit_code'] != 0):
            raise Inconclusive('Repeat bootstrap successful exit status unavailable')
        if command.get('outcome') != 'passed':
            report.update(reason='repeat_bootstrap_'+str(command.get('outcome')),
                          verdict='inconclusive')
            return report
        stage = 'observation'
        after = copy.deepcopy(observe(sandbox, monotonic_deadline=monotonic_deadline,
                                      wall_deadline=wall_deadline))
        check(0)
        stage = 'verification'
        if verify(before, after, expected_case) is not None:
            raise Inconclusive('Independent bootstrap verifier returned an unsupported result')
        check(0)
        report.update(outcome='repeat_bootstrap_checked',verdict='pass',abort_suite=False)
    except AssertionError:
        if stage == 'verification':
            report['preservation_mismatch_observed'] = True
            try:
                check(0)
                report.update(outcome='repeat_bootstrap_checked',reason='preservation_mismatch',verdict='fail')
            except Exception as error:
                report.update(reason='preservation_settlement_unavailable',error_type=type(error).__name__)
        else:
            report.update(reason='independent_precondition_incomplete')
    except Exception as error:
        report.update(reason='repeat_bootstrap_unavailable',error_type=type(error).__name__)
    finally:
        if command is not None:
            report['command_outcome']=command.get('outcome')
            report['command_exit_code']=command.get('exit_code')
        report['stage']=stage
        atomic_json(attempt.directory/'repeat-bootstrap-result.json',report)
    return report
