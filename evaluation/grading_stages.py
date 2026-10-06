"""Sequential fresh deployments of one frozen registry within one grading budget."""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time

from .deployment import grade_capture, verify_capture
from .evidence import Attempt, atomic_json, collect, positive, private_file
from .grading import Suite, run_suite, select_cases
from .sandbox import Sandbox, disjoint, sandbox_create_argv
from .source_binding import open_directory
from .preparation import read_regular
from .verdicts import Inconclusive
from .watchdog import Guard, NAME, stop_and_verify


STAGE_OPTIONS = {
    'bootstrap_seconds', 'fixture_loader', 'fault_workloads', 'kubectl_prefix',
    'fault_runtime_factory', 'fault_service_probes', 'fault_audit', 'audit_observer',
    'audit_runtime_factory', 'browser_resolver', 'browser_binding_factory',
    'fault_storage_worker_restart', 'job_observer', 'job_runtime_factory',
    'job_staging', 'staging_runtime_factory', 'security_observer',
    'security_runtime_factory', 'ops_resolver', 'ops_runtime_factory',
}


def suite_identity(suite):
    data = dict(root=str(suite.root), path=str(suite.path), digest=suite.digest,
                manifest=suite.manifest, cases=suite.cases, packages=suite.packages,
                criteria=sorted(suite.criteria), complete=sorted(suite.complete),
                approved=suite.approved)
    return hashlib.sha256(json.dumps(data, sort_keys=True, allow_nan=False).encode()).hexdigest()


def parent_identity(path):
    descriptor = open_directory(path.parent)
    try:
        metadata = os.fstat(descriptor)
        return metadata.st_dev, metadata.st_ino
    finally:
        os.close(descriptor)



def matching_resource(resource, stage, specification, port):
    return (isinstance(resource, dict) and resource.get('name') == stage['name']
            and resource.get('project') == str(stage['project'])
            and resource.get('specification') == str(specification)
            and resource.get('manual_stop') == ['sbx','stop',stage['name']]
            and type(resource.get('port')) is int and resource['port'] == port
            and resource.get('primary_workspace') is None
            and resource.get('project_readonly') is False)


def grade_stages(attempt, source, inventory, specification, suite, stages, *, port,
                 grading_seconds=5400, development=False, sandbox_factory=Sandbox,
                 guard_factory=Guard, command_runner=collect, deployment=grade_capture,
                 stop_resource=stop_and_verify,
                 sequence_check=None,
                 monotonic=time.monotonic, wall=time.time):
    """Operator API only; no model/launch entrypoint or readiness override.

    Stages exactly partition one registry. Source/specification must already be
    independently captured/prepared after verified builder termination. The caller
    owns the parent workspace and native fixture/capability adapters. The outer
    owner must interrupt arbitrary callbacks/IO; cleanup runs even after expiry.
    """
    if (attempt.directory / 'grading-stages-intent.json').exists() or (attempt.directory / 'grading-stages-intent.json').is_symlink():
        raise FileExistsError('Fresh grading sequence already has an exclusive intent')
    positive(grading_seconds, 'shared grading budget')
    if grading_seconds > 5400:
        raise ValueError('Shared grading budget exceeds proposed first-test ceiling')
    if type(development) is not bool or not isinstance(suite, Suite):
        raise ValueError('Protected registry and explicit development mode required')
    if not suite.approved and not development:
        raise ValueError('Independent human suite approval required')
    if not all(callable(value) for value in (sandbox_factory, guard_factory, command_runner,
                                              deployment, stop_resource, monotonic, wall)):
        raise ValueError('Trusted grading adapters and clocks required')
    if sequence_check is not None and not callable(sequence_check):
        raise ValueError('Trusted sequence identity check required')
    suite.verify()
    frozen = copy.deepcopy(suite)
    expected_suite = suite_identity(frozen)
    source = Path(source).resolve(strict=True)
    specification = Path(specification).resolve(strict=True)
    disjoint(source, specification)
    inventory = copy.deepcopy(inventory)
    verify_capture(source, inventory)
    if not isinstance(stages, (list, tuple)) or not stages:
        raise ValueError('Nonempty fresh grading stage partition required')
    prepared = []; assigned = []; names = set(); identifiers = set(); projects = []
    for stage in stages:
        if (not isinstance(stage, dict) or not {'id','name','project','case_ids','target'} <= set(stage)
                or not set(stage) <= {'id','name','project','case_ids','target','options'}):
            raise ValueError('Explicit stage identity/resource/case/target fields required')
        identifier, name = stage['id'], stage['name']
        if (not isinstance(identifier, str) or not re.fullmatch('[a-z][a-z0-9-]{0,57}', identifier)
                or identifier in identifiers or not isinstance(name, str)
                or not NAME.fullmatch(name) or '-grader-' not in name or name in names):
            raise ValueError('Unique grading stage and planned grader names required')
        project = Path(stage['project'])
        if project.is_symlink() or project.exists():
            raise ValueError('Fresh stage project must not already exist')
        project = project.resolve()
        for protected in (source, specification, frozen.root, attempt.directory,
                          Path(__file__).resolve().parents[1], *projects):
            disjoint(project, protected)
        expected_parent = parent_identity(project)
        if (attempt.directory / identifier).exists() or (attempt.directory / identifier).is_symlink():
            raise ValueError('Fresh stage evidence directory required')
        selected = [case['id'] for case in select_cases(frozen, stage['case_ids'])]
        if not isinstance(stage.get('options', {}), dict):
            raise ValueError('Stage options must be a dictionary')
        options = dict(stage.get('options', {}))
        if not set(options) <= STAGE_OPTIONS or not isinstance(stage['target'], dict):
            raise ValueError('Trusted bounded stage options and target required')
        if 'bootstrap_seconds' in options:
            positive(options['bootstrap_seconds'], 'stage bootstrap bound')
            if options['bootstrap_seconds'] > 1800:
                raise ValueError('Stage bootstrap exceeds proposed preparation ceiling')
        target = copy.deepcopy(stage['target'])
        json.dumps(target, allow_nan=False)
        create_argv = sandbox_create_argv(project, specification, name=name, port=port, role='grader')
        prepared.append(dict(id=identifier, name=name, project=project, case_ids=selected,
                             target=target, options=options, parent=expected_parent, create_argv=create_argv))
        assigned.extend(selected);names.add(name);identifiers.add(identifier);projects.append(project)
    if len(set(assigned)) != len(assigned) or set(assigned) != {case['id'] for case in frozen.cases}:
        raise ValueError('Fresh stages must partition every registered case exactly once')
    started, wall_started = monotonic(), wall()
    owner = os.getpid()
    previous = [started, wall_started]
    def remaining():
        values = monotonic(), wall()
        if (os.getpid() != owner or any(type(value) not in (int,float) or not math.isfinite(value)
                                        for value in (*values, started, wall_started))):
            raise Inconclusive('Shared grading owner/clocks unavailable')
        if any(value < before for value, before in zip(values,previous)):
            raise Inconclusive('Shared grading clock moved backwards')
        previous[:] = values
        return min(started + grading_seconds - values[0], wall_started + grading_seconds - values[1])
    if remaining() <= 0:
        raise Inconclusive('Shared grading budget unavailable')
    def common_check():
        if sequence_check is not None and sequence_check() is not True:
            raise Inconclusive('Planned grading sequence binding unavailable')
        suite.verify()
        frozen.verify()
        if suite_identity(suite) != expected_suite or suite_identity(frozen) != expected_suite:
            raise Inconclusive('Shared protected registry identity changed')
        verify_capture(source, inventory)
    # Exclusive intent prevents reuse of any completed or interrupted sequence.
    summary = [dict(id=stage['id'], sandbox=stage['name'], project=str(stage['project']),
                    case_ids=stage['case_ids'], create_argv=stage['create_argv'],
                    option_names=sorted(stage['options'])) for stage in prepared]
    with private_file(attempt.directory / 'grading-stages-intent.json') as stream:
        stream.write(json.dumps(dict(schema_version=1, suite_sha256=frozen.digest,
            source_inventory_sha256=hashlib.sha256(json.dumps(inventory,sort_keys=True).encode()).hexdigest(),
            grading_seconds=grading_seconds, stages=summary),sort_keys=True).encode())
        stream.flush();os.fsync(stream.fileno())
    results = {}; records = []; protocol_valid = True; aborted = False; reason = None; interrupted = None
    try:
        common_check()
        for stage in prepared:
            allowance = remaining()
            if allowance <= 0:
                raise Inconclusive('Shared grading deadline expired')
            common_check()
            if parent_identity(stage['project']) != stage['parent'] or stage['project'].exists() or stage['project'].is_symlink():
                raise Inconclusive('Fresh stage workspace unavailable')
            phase_suite = copy.deepcopy(frozen)
            owned = {}
            def phase_factory(*args, **kwargs):
                if owned:
                    raise Inconclusive('Stage sandbox creation factory cannot be reused')
                box = sandbox_factory(*args, **kwargs, planned_name=stage['name'])
                if (box.name != stage['name'] or Path(box.project) != stage['project']
                        or Path(box.specification) != specification
                        or box.creation_attempted is not False or box.stopped is not False
                        or box.create_argv() != stage['create_argv']):
                    raise Inconclusive('Fresh planned stage sandbox binding unavailable')
                descriptor = open_directory(stage['project'])
                try:
                    metadata = os.fstat(descriptor)
                    owned.update(box=box, root=(metadata.st_dev,metadata.st_ino))
                finally:
                    os.close(descriptor)
                return box
            def phase_runner(*args, **kwargs):
                return run_suite(*args, **kwargs, case_ids=stage['case_ids'])
            record = dict(id=stage['id'], sandbox=stage['name'], case_ids=stage['case_ids'],
                          outcome='stage_incomplete', creation_attempted=False, termination_verified=False)
            records.append(record)
            with Attempt(attempt.directory / stage['id'], dict(purpose='fresh protected grading stage',
                         suite_sha256=frozen.digest, sandbox=stage['name'], case_ids=stage['case_ids'])) as child:
                child.transition('preflight')
                try:
                    observed = deployment(child, source, copy.deepcopy(inventory), specification,
                        stage['project'], phase_suite, copy.deepcopy(stage['target']), port=port,
                        grading_seconds=min(allowance,remaining()), development=development,
                        sandbox_factory=phase_factory, guard_factory=guard_factory,
                        command_runner=command_runner, suite_runner=phase_runner, **stage['options'])
                    if isinstance(observed, dict):
                        atomic_json(child.directory / 'stage-observations.json', observed)
                    values = observed.get('case_results') if isinstance(observed,dict) else None
                    if isinstance(values,dict):
                        if not set(values) <= set(stage['case_ids']):
                            raise Inconclusive('Stage results escaped assigned cases')
                        frozen.aggregate(values)
                        results.update(copy.deepcopy(values))
                    resource = json.loads(read_regular(child.directory / 'grader-resource.json',65536,lambda:None))
                    if not matching_resource(resource,stage,specification,port):
                        raise Inconclusive('Stage private creation intent changed scope')
                    record['creation_attempted'] = True
                    box = owned.get('box')
                    if (box is None or box.name != stage['name'] or Path(box.project) != stage['project']
                            or Path(box.specification) != specification or box.creation_attempted is not True
                            or box.stopped is not True):
                        raise Inconclusive('Stage owned sandbox lifetime not settled')
                    descriptor = open_directory(stage['project'])
                    try:
                        metadata = os.fstat(descriptor)
                        if (metadata.st_dev,metadata.st_ino) != owned['root']:
                            raise Inconclusive('Stage owned project root changed')
                    finally:
                        os.close(descriptor)
                    if (not isinstance(observed,dict) or not isinstance(observed.get('cleanup'),dict)
                            or observed['cleanup'].get('remote_termination_verified') is not True
                            or observed.get('manual_stop') != ['sbx','stop',stage['name']]):
                        raise Inconclusive('Stage remote termination or resource scope unavailable')
                    record['termination_verified'] = True
                    common_check()
                    phase_suite.verify()
                    if suite_identity(phase_suite) != expected_suite:
                        raise Inconclusive('Stage protected registry cache changed')
                    if parent_identity(stage['project']) != stage['parent']:
                        raise Inconclusive('Stage workspace parent changed')
                    if remaining() <= 0:
                        raise Inconclusive('Shared grading deadline expired after stage settlement')
                    if (observed.get('suite_sha256') != frozen.digest
                            or observed.get('suite_approved') is not frozen.approved
                            or observed.get('selected_case_ids') != stage['case_ids']
                            or type(observed.get('aborted')) is not bool
                            or observed.get('outcome') not in ('graded','grading_incomplete')
                            or 'error_type' in observed or not isinstance(values,dict)
                            or not set(values) <= set(stage['case_ids'])):
                        raise Inconclusive('Stage observations unavailable or outside assigned registry')
                    record.update(outcome='stage_observations_settled', observed_case_ids=sorted(values))
                    if observed['aborted'] or set(values) != set(stage['case_ids']):
                        aborted = True;reason = 'stage_aborted_or_incomplete'
                        break
                except BaseException as error:
                    record['error_type'] = type(error).__name__
                    raise
                finally:
                    box = owned.get('box')
                    if box is not None:
                        # An adapter's mutable flag alone cannot authorize cleanup.
                        # Use the private pre-create resource intent, which is absent
                        # when a planned-name collision refuses before creation.
                        try:
                            resource = json.loads(read_regular(child.directory / 'grader-resource.json',65536,lambda:None))
                            if matching_resource(resource,stage,specification,port):
                                record['creation_attempted'] = True
                                if box.stopped is not True:
                                    box.name,box.project,box.specification = stage['name'],stage['project'],specification
                                    box.creation_attempted = True
                                    cleanup = stop_resource(child,stage['name'],'sbx')
                                    verified = isinstance(cleanup,dict) and cleanup.get('remote_termination_verified') is True
                                    box.stopped = verified
                                    record['fallback_termination_verified'] = verified
                                    record['termination_verified'] = verified
                        except FileNotFoundError:
                            record['creation_attempted'] = False
                        except BaseException as error:
                            record['fallback_cleanup_error'] = type(error).__name__
                    child.transition('failed');child.finish(record)
        common_check()
        if remaining() <= 0:
            raise Inconclusive('Shared grading deadline expired before aggregation')
    except BaseException as error:
        protocol_valid = False;aborted = True;reason = type(error).__name__
        if not isinstance(error, Exception):interrupted = error
    finally:
        elapsed = dict(monotonic_elapsed_seconds=None, wall_elapsed_seconds=None)
        try:
            attempt.emit('grader','stages.aggregate',dict(stage_count=len(records),observed_case_count=len(results)))
            values = monotonic(), wall()
            if all(type(value) in (int,float) and math.isfinite(value) for value in values):
                elapsed = dict(monotonic_elapsed_seconds=values[0]-started,
                               wall_elapsed_seconds=values[1]-wall_started)
            if remaining() <= 0:
                protocol_valid = False;aborted = True;reason = 'shared_grading_deadline_expired'
        except BaseException as error:
            elapsed = dict(monotonic_elapsed_seconds=None, wall_elapsed_seconds=None)
            protocol_valid = False;aborted = True;reason = 'shared_grading_final_settlement_unavailable'
            if not isinstance(error, Exception):interrupted = error
        if not protocol_valid:
            results = {identifier:dict(case_id=identifier,verdict='inconclusive',
                       reason='fresh_grading_sequence_unsettled', observed_verdict=value.get('observed_verdict',value['verdict']))
                       for identifier,value in results.items()}
        report = frozen.aggregate(results)
        report.update(outcome=('graded' if protocol_valid and not aborted
                      and all(value['verdict'] in ('pass','fail') for value in report['criteria'].values())
                      else 'grading_incomplete'), case_results=results, stages=records,
                      protocol_valid=protocol_valid, aborted=aborted, reason=reason,
                      grading_seconds=grading_seconds, **elapsed,
                      limits='One registry/source, exact case partition and shared grading budget. No model, readiness override, native fixture/source-image proof or launch authority; outer owner must interrupt callbacks/IO. Cleanup may finish after budget expiry without acceptance.')
        if not protocol_valid:
            report['accepted_packages']=[];report['project_success']=False
        atomic_json(attempt.directory / 'grading-stages-result.json', report)
    if interrupted is not None:raise interrupted
    return report
