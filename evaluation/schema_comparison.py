"""Guarded source/replay-bound catalog comparison for foundation migration adapters."""
import copy
import hashlib
import json
import re
import time

from .evidence import atomic_json
from .verdicts import Inconclusive


BINDING_FIELDS = {'capture_sha256', 'migration_plan_sha256', 'replay_receipt_sha256',
                  'baseline_database_identity_sha256', 'live_database_identity_sha256'}
CATALOG_FIELDS = {'outcome', 'catalog_sha256', 'table_count', 'column_count', 'extension_count',
                  'server_version_num', 'migration_current_verified', 'data_verified',
                  'privileges_verified', 'limits'}


def binding_record(value):
    if (not isinstance(value, dict) or set(value) != BINDING_FIELDS
            or any(not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{64}', v) for v in value.values())
            or value['baseline_database_identity_sha256'] == value['live_database_identity_sha256']):
        raise ValueError('Distinct independently bound replay/application databases required')
    return copy.deepcopy(value)


def catalog_record(value):
    if (not isinstance(value, dict) or set(value) != CATALOG_FIELDS
            or value['outcome'] != 'schema_catalog_observed'
            or not isinstance(value['catalog_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['catalog_sha256'])
            or type(value['table_count']) is not int or not 1 <= value['table_count'] <= 64
            or type(value['column_count']) is not int or not 1 <= value['column_count'] <= 4096
            or type(value['extension_count']) is not int or not 0 <= value['extension_count'] <= 64
            or type(value['server_version_num']) is not int or not 160000 <= value['server_version_num'] < 180000
            or any(value[k] is not False for k in ('migration_current_verified', 'data_verified', 'privileges_verified'))
            or not isinstance(value['limits'], str) or len(value['limits']) > 4096):
        raise Inconclusive('Complete supported catalog snapshot unavailable')
    return {key:value[key] for key in ('catalog_sha256', 'table_count', 'column_count',
                                      'extension_count', 'server_version_num')}


def compare_schema_replay(attempt, *, baseline_reader, live_reader, binding,
                          lifetime_check, source_check, replay_check, live_check,
                          label='foundation-migration-comparison'):
    """Read baseline/live/live/baseline, then repeat all independent bindings.

    source_check(binding,reserve) verifies the captured source and complete ordered
    migration plan. replay_check verifies the immutable receipt, successful full
    replay on the originally empty independent database, original peer/schema
    identity and baseline quiescence. live_check verifies the actual application
    database identity and deployment/source mapping. All return exact True or
    raise. Their outer owner bounds callbacks and filesystem I/O with a watchdog.

    This function neither executes nor discovers migrations, nor authenticates
    self-reported builder receipts. Use protected operator receipts and readers.
    A matching supported catalog is not proof of arbitrary migration semantics,
    privileges, data migrations, extension code, history or an atomic snapshot.
    """
    selected = binding_record(binding)
    callbacks = (source_check, replay_check, live_check)
    if (not all(callable(v) for v in (*callbacks, lifetime_check, baseline_reader, live_reader))
            or not isinstance(label, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)):
        raise ValueError('Independent bounded schema comparison interfaces required')
    started, wall_started = time.monotonic(), time.time()
    result = dict(outcome='migration_comparison_incomplete', schema_matches_replay=None,
                  snapshots_stable=False, bindings_verified=False, schema_identity=None,
                  migration_current_verified=False, atomic_snapshot_verified=False,
                  data_verified=False, privileges_verified=False,
                  binding_sha256=hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest(),
                  limits='Repeated supported catalog snapshots and independent source/replay/live bindings; '
                         'no migration history, arbitrary/data migration, extension code, privilege or atomicity proof.')
    def checked(reserve):
        if max(time.monotonic()-started, time.time()-wall_started)+reserve > 90:
            raise Inconclusive('Schema comparison deadline unavailable')
        if lifetime_check(reserve) is not True:raise Inconclusive('Schema comparison lifetime unavailable')
        for callback in callbacks:
            # Give each guard its own copy; a callback cannot silently rewrite
            # the binding passed to a later guard or reported in the final digest.
            if callback(copy.deepcopy(selected), reserve) is not True:
                raise Inconclusive('Independent source/replay/database binding unavailable')
    try:
        checked(65)
        snapshots = []
        for reader in (baseline_reader, live_reader, live_reader, baseline_reader):
            if max(time.monotonic()-started, time.time()-wall_started)+15 > 90:
                raise Inconclusive('Schema read deadline unavailable')
            snapshots.append(catalog_record(reader(timeout=15)))
        checked(0)
        first_baseline, first_live, last_live, last_baseline = snapshots
        stable = first_baseline == last_baseline and first_live == last_live
        if not stable or first_baseline['server_version_num'] != first_live['server_version_num']:
            raise Inconclusive('Catalog snapshot changed or server versions differ')
        matches = first_baseline == first_live
        identity = hashlib.sha256(json.dumps(dict(binding=selected, live_catalog=first_live), sort_keys=True).encode()).hexdigest()
        result.update(outcome='migration_catalog_comparison_observed', schema_matches_replay=matches,
                      snapshots_stable=True, bindings_verified=True, schema_identity=identity,
                      baseline_catalog=first_baseline, live_catalog=first_live)
    except Exception as error:
        result['error_type'] = type(error).__name__
    finally:
        result['elapsed_seconds'] = max(time.monotonic()-started, time.time()-wall_started)
        atomic_json(attempt.directory/(label+'.json'), result)
    return result
