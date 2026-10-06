"""Parent-owned audit gate lifecycle; no database capability reaches a worker."""
from contextlib import contextmanager
import copy
import hashlib
import uuid

from .database_probe import identifier, privilege_sql, insert_canary_sql, audit_insert_fault_sql
from .evidence import atomic_json
from .faults import FaultSetupError, FaultRestoreError

COMMAND_SECONDS = 15
COMMAND_RESERVE = 20
FAULT_RESERVE = 210


@contextmanager
def audit_insert_failure(attempt, binding, *, execute, check):
    """Require a trusted, guarded connection transport and explicit operator mapping.

    execute(identity, sql, timeout=...) accepts only 'runtime'/'operator' identities,
    completes the entire bounded SQL command, checks its exit status and returns
    one parsed JSON object. Credentials and arbitrary SQL never come from workers.
    check(reserve_seconds) verifies exact peer identity and disposable-sandbox guard
    lifetime before every command. Process death still requires that outer guard.
    Use a separate Attempt: the grader and broker may write concurrently.
    """
    binding = copy.deepcopy(binding)
    required = {'schema', 'table', 'table_oid', 'database_name', 'runtime_user', 'session_user', 'operator_user', 'operator_session_user', 'canary'}
    if not isinstance(binding, dict) or set(binding) != required:
        raise ValueError('Incomplete operator audit binding')
    for key in ('schema', 'table', 'database_name', 'runtime_user', 'session_user', 'operator_user', 'operator_session_user'):
        identifier(binding[key])
    name = 'factory_audit_fault_' + uuid.uuid4().hex
    schema, table, oid = binding['schema'], binding['table'], binding['table_oid']
    install_sql = audit_insert_fault_sql(schema, table, oid, name, action='install')
    canary_sql = insert_canary_sql(schema, table, binding['canary'])
    metadata_sql = privilege_sql(schema, table)
    scope = {key: value for key, value in binding.items() if key != 'canary'}
    scope['constraint_name'] = name
    atomic_json(attempt.directory / 'audit-restoration-plan.json', scope)
    result = {'fault_established': False, 'mutation_attempted': False, 'restoration_verified': False}
    gate_oid = None

    def run(phase, identity, sql):
        check(COMMAND_RESERVE)
        attempt.emit('controller', 'audit.command.started', {'phase': phase, 'identity': identity,
                     'sql_sha256': hashlib.sha256(sql.encode()).hexdigest()})
        try:
            value = execute(identity, sql, timeout=COMMAND_SECONDS)
        except Exception:
            raise FaultSetupError('Database command incomplete: ' + phase) from None
        if not isinstance(value, dict):
            raise FaultSetupError('Database observation unavailable: ' + phase)
        attempt.emit('controller', 'audit.command.finished', {'phase': phase})
        return value

    def identity_matches(value):
        return (value.get('current_user') == binding['runtime_user']
                and value.get('session_user') == binding['session_user']
                and value.get('database_name') == binding['database_name'])

    def relation_matches(value):
        return (identity_matches(value) and value.get('relation_found') is True
                and str(value.get('relation_oid')) == str(oid) and value.get('relation_kind') == 'r')

    def insertion_succeeded(value):
        return (identity_matches(value) and value.get('outcome') == 'insert_executed'
                and type(value.get('rows')) is int and value['rows'] == 1)

    try:
        check(FAULT_RESERVE)
        if not relation_matches(run('baseline-identity', 'runtime', metadata_sql)):
            raise FaultSetupError('Runtime database/table identity differs from operator binding')
        if not insertion_succeeded(run('baseline-insert', 'runtime', canary_sql)):
            raise FaultSetupError('Runtime audit baseline insertion unavailable')
        operator = run('operator-identity', 'operator', metadata_sql)
        if not (operator.get('database_name') == binding['database_name']
                and operator.get('current_user') == binding['operator_user']
                and operator.get('session_user') == binding['operator_session_user']
                and operator.get('relation_found') is True and str(operator.get('relation_oid')) == str(oid)
                and operator.get('relation_kind') == 'r'):
            raise FaultSetupError('Operator database/table identity differs from binding')
        # Persist intent before a remote command can commit. A missing reply is
        # uncertain, never evidence that installation did not happen.
        result['mutation_attempted'] = True
        atomic_json(attempt.directory / 'audit-state.json', result)
        installed = run('install', 'operator', install_sql)
        if (installed.get('outcome') != 'audit_gate_installed'
                or str(installed.get('table_oid')) != str(oid) or installed.get('constraint_name') != name):
            raise FaultSetupError('Audit installation identity unavailable')
        try:
            candidate = installed['constraint_oid']
            if type(candidate) not in (int, str) or str(int(candidate)) != str(candidate):
                raise ValueError('Invalid OID')
            gate_oid = int(candidate)
            restore_sql = audit_insert_fault_sql(schema, table, oid, name, action='remove', constraint_oid=gate_oid)
        except (KeyError, ValueError, TypeError):
            gate_oid = None
            raise FaultSetupError('Audit constraint identity unavailable') from None
        atomic_json(attempt.directory / 'audit-constraint.json', dict(scope, constraint_oid=gate_oid))
        failed = run('fault-insert', 'runtime', canary_sql)
        if not (identity_matches(failed) and failed.get('outcome') == 'insert_rejected'
                and failed.get('sqlstate') == '23514' and failed.get('constraint_name') == name
                and failed.get('schema') == schema and failed.get('table') == table):
            raise FaultSetupError('Exact runtime audit insertion failure not observed')
        result['fault_established'] = True
        yield {'audit_insert_failure_verified': True, 'audit_constraint_canary': name}
    except BaseException as error:
        result['body_error_type'] = type(error).__name__
        raise
    finally:
        try:
            if result['mutation_attempted']:
                if gate_oid is None:
                    raise FaultRestoreError('Audit installation outcome unknown; dispose grading environment')
                restored = run('restore', 'operator', restore_sql)
                if (restored.get('outcome') != 'audit_gate_removed'
                        or str(restored.get('table_oid')) != str(oid)):
                    raise FaultRestoreError('Audit gate removal unverified')
                if not insertion_succeeded(run('recovery-insert', 'runtime', canary_sql)):
                    raise FaultRestoreError('Runtime audit insertion did not recover')
                if not relation_matches(run('recovery-identity', 'runtime', metadata_sql)):
                    raise FaultRestoreError('Runtime identity changed during restoration')
                result['restoration_verified'] = True
        except BaseException as error:
            result['restoration_error_type'] = type(error).__name__
            raise FaultRestoreError('Audit fault restoration uncertain; abort grading') from error
        finally:
            atomic_json(attempt.directory / 'audit-result.json', result)
