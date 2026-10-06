"""AC-003 checks inside one already-owned disposable grading copy."""
import copy
import os
from pathlib import Path
import time

from .evidence import atomic_json, collect, positive
from .verdicts import Inconclusive
from .watchdog import NAME


def verify_disposable_operations(attempt, sandbox, guard, *, observe, verify_destroyed,
                                 failure_setup, source_check, monotonic_deadline,
                                 wall_deadline, test_timeout=1800, destroy_timeout=900,
                                 command_runner=collect, monotonic=time.monotonic,
                                 wall=time.time):
    """Verify test failure propagation and scoped repeatable destroy.

    The caller owns a disposable post-capture project and an unrelated canary in
    the same independently observed scope. `failure_setup` is a trusted context
    manager that injects one known failing public test without selecting commands.
    The outer owner must interrupt callbacks/I/O and later stop the grading sbx.
    """
    for value,label in ((monotonic_deadline,'monotonic deadline'),
                        (wall_deadline,'wall deadline'),(test_timeout,'test timeout'),
                        (destroy_timeout,'destroy timeout')):
        positive(value,label)
    if (not all(callable(value) for value in (observe,verify_destroyed,failure_setup,
                                               source_check,command_runner,monotonic,wall))
            or not NAME.fullmatch(sandbox.name) or '-grader-' not in sandbox.name):
        raise ValueError('Independent disposable operations binding required')
    owner=os.getpid();identity=(sandbox.name,str(sandbox.project));previous=[monotonic(),wall()]
    report=dict(outcome='disposable_operations_incomplete',verdict='inconclusive',abort_suite=True,
                stage='precondition')
    def check(reserve=0, *, source=False):
        values=[monotonic(),wall()]
        if (os.getpid()!=owner or values[0]<previous[0] or values[1]<previous[1]
                or (sandbox.name,str(sandbox.project))!=identity or sandbox.stopped
                or not sandbox.creation_attempted or guard.process.poll() is not None
                or (guard.directory/'release.json').exists() or (guard.directory/'result.json').exists()
                or min(monotonic_deadline-values[0],wall_deadline-values[1])<=reserve):
            raise Inconclusive('Disposable operations lifetime unavailable')
        previous[:]=values
        if source:
            try:verified=source_check(reserve)
            except Exception:raise Inconclusive('Captured source check unavailable') from None
            if verified is not True:raise Inconclusive('Captured source check unavailable')
        return min(monotonic_deadline-values[0],wall_deadline-values[1])
    def command(label,relative,timeout):
        allowance=min(timeout,check(1)-1)
        argv=sandbox.exec_argv([relative]);expected=['sbx','exec','-w',identity[1],identity[0],relative]
        if argv!=expected:raise Inconclusive('Disposable command escaped owned sandbox')
        return command_runner(attempt,label,argv,cwd=Path(__file__).resolve().parents[1],timeout=allowance)
    try:
        check(1,source=True);before=copy.deepcopy(observe(sandbox,phase='before',
            monotonic_deadline=monotonic_deadline,wall_deadline=wall_deadline));check(1,source=True)
        report['stage']='test_failure_setup'
        with failure_setup(sandbox,monotonic_deadline=monotonic_deadline,
                           wall_deadline=wall_deadline) as receipt:
            if receipt!={'known_failure_injected':True,'scope_verified':True}:
                raise Inconclusive('Known public-test failure injection unavailable')
            report['stage']='test_failure'
            tested=command('disposable-test-failure','./ops/test.sh',test_timeout)
        if (tested.get('outcome')!='failed' or type(tested.get('exit_code')) is not int
                or tested['exit_code']==0):
            if tested.get('outcome')=='passed' and tested.get('exit_code')==0:
                raise AssertionError('Documented test command hid a known test failure')
            raise Inconclusive('Known test failure command result unavailable')
        check(1);report['test_exit_code']=tested['exit_code']
        report['stage']='first_destroy';first=command('disposable-destroy-first','./ops/destroy.sh',destroy_timeout)
        if first.get('outcome')!='passed' or type(first.get('exit_code')) is not int or first['exit_code']!=0:
            raise AssertionError('First documented destroy command failed')
        check(1);after=copy.deepcopy(observe(sandbox,phase='after-first-destroy',
            monotonic_deadline=monotonic_deadline,wall_deadline=wall_deadline));check(1)
        if verify_destroyed(before,after) is not None:raise Inconclusive('Destroy verifier returned unsupported result')
        report['stage']='repeat_destroy';second=command('disposable-destroy-repeat','./ops/destroy.sh',destroy_timeout)
        if second.get('outcome')!='passed' or type(second.get('exit_code')) is not int or second['exit_code']!=0:
            raise AssertionError('Repeated documented destroy command failed')
        check(0);final=copy.deepcopy(observe(sandbox,phase='after-repeat-destroy',
            monotonic_deadline=monotonic_deadline,wall_deadline=wall_deadline));check(0)
        if verify_destroyed(before,final) is not None:raise Inconclusive('Repeat destroy verifier returned unsupported result')
        report.update(outcome='disposable_operations_checked',verdict='pass',abort_suite=False,stage='verified')
    except AssertionError as error:
        try:
            check(0);report.update(outcome='disposable_operations_checked',verdict='fail',reason=str(error)[:500])
        except Exception as settlement:
            report.update(verdict='inconclusive',reason='disposable_operations_settlement_unavailable',error_type=type(settlement).__name__)
    except Exception as error:
        report.update(reason='disposable_operations_unavailable',error_type=type(error).__name__)
    atomic_json(attempt.directory/'disposable-operations-result.json',report)
    return report
