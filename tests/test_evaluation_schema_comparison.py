"""Independent replay/source/live drift cannot turn into a migration match."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.evidence import Attempt
from evaluation.schema_comparison import binding_record, compare_schema_replay


BINDING = dict(capture_sha256='a'*64,migration_plan_sha256='b'*64,replay_receipt_sha256='c'*64,
               baseline_database_identity_sha256='d'*64,live_database_identity_sha256='e'*64)
CATALOG = dict(outcome='schema_catalog_observed',catalog_sha256='f'*64,table_count=11,column_count=78,
               extension_count=1,server_version_num=170006,migration_current_verified=False,
               data_verified=False,privileges_verified=False,limits='Declared supported catalog')


class SchemaComparisonTest(unittest.TestCase):
    def run_comparison(self, baseline=None, live=None, guards=None):
        calls=[];guard_counts={name:0 for name in ('source','replay','live')}
        def guard(name):
            def check(binding,reserve):
                guard_counts[name]+=1
                if guards and name in guards:return guards[name](binding,reserve,guard_counts[name])
                return binding==BINDING
            return check
        def reader(name,values):
            observations=iter(values or [copy.deepcopy(CATALOG),copy.deepcopy(CATALOG)])
            def read(*,timeout):
                self.assertEqual(timeout,15);calls.append(name);return next(observations)
            return read
        with tempfile.TemporaryDirectory() as temporary:
            with Attempt(Path(temporary)/'evidence',{}) as attempt:
                result=compare_schema_replay(attempt,baseline_reader=reader('baseline',baseline),
                    live_reader=reader('live',live),binding=BINDING,lifetime_check=lambda reserve:True,
                    source_check=guard('source'),replay_check=guard('replay'),live_check=guard('live'))
                self.assertTrue((attempt.directory/'foundation-migration-comparison.json').is_file())
                attempt.transition('failed');attempt.finish(dict(outcome='fixture_completed'))
        return result,calls,guard_counts

    def test_matching_bracketed_catalogs_require_each_independent_binding_twice(self):
        result,calls,guards=self.run_comparison()
        self.assertTrue(result['schema_matches_replay']);self.assertTrue(result['bindings_verified'])
        self.assertEqual(calls,['baseline','live','live','baseline'])
        self.assertEqual(guards,dict(source=2,replay=2,live=2))
        for field in ('migration_current_verified','atomic_snapshot_verified','data_verified','privileges_verified'):
            self.assertFalse(result[field])

    def test_stable_schema_mismatch_is_observed_false_instead_of_unknown(self):
        changed=dict(CATALOG,catalog_sha256='1'*64)
        result,_,_=self.run_comparison(live=[changed,changed])
        self.assertEqual(result['outcome'],'migration_catalog_comparison_observed')
        self.assertFalse(result['schema_matches_replay']);self.assertTrue(result['snapshots_stable'])

    def test_baseline_or_live_drift_and_different_server_versions_are_unknown(self):
        changed=dict(CATALOG,catalog_sha256='1'*64)
        for options in (dict(baseline=[CATALOG,changed]),dict(live=[CATALOG,changed]),
                        dict(live=[dict(CATALOG,server_version_num=170007)]*2)):
            with self.subTest(options=options):
                result,_,_=self.run_comparison(**options)
                self.assertIsNone(result['schema_matches_replay']);self.assertFalse(result['bindings_verified'])

    def test_each_guard_refusal_before_or_after_reads_invalidates_comparison(self):
        for name in ('source','replay','live'):
            for failure_count in (1,2):
                with self.subTest(name=name,count=failure_count):
                    result,calls,_=self.run_comparison(guards={name:lambda binding,reserve,count:count!=failure_count})
                    self.assertIsNone(result['schema_matches_replay']);self.assertIsNone(result['schema_identity'])
                    self.assertEqual(len(calls),0 if failure_count==1 else 4)

    def test_guard_mutation_does_not_rewrite_other_guards_bindings(self):
        def mutate(binding,reserve,count):binding['capture_sha256']='0'*64;return True
        result,_,_=self.run_comparison(guards={'source':mutate})
        self.assertTrue(result['schema_matches_replay'])
        self.assertEqual(BINDING['capture_sha256'],'a'*64)

    def test_missing_unsupported_or_forged_catalog_refuses(self):
        for altered in ({},dict(CATALOG,table_count=True),dict(CATALOG,migration_current_verified=True),
                        dict(CATALOG,catalog_sha256='invalid')):
            result,_,_=self.run_comparison(live=[altered,altered]);self.assertIsNone(result['schema_matches_replay'])

    def test_same_database_invalid_hash_and_extra_binding_fields_refuse(self):
        for binding in (dict(BINDING,live_database_identity_sha256='d'*64),
                        dict(BINDING,capture_sha256='invalid'),dict(BINDING,unreviewed=True)):
            with self.assertRaises(ValueError):binding_record(binding)

    def test_deadline_refuses_reads_and_keeps_result_unknown(self):
        with patch('evaluation.schema_comparison.time') as clock:
            clock.monotonic.side_effect=[0,100,100];clock.time.return_value=0
            result,calls,_=self.run_comparison()
        self.assertEqual(calls,[]);self.assertIsNone(result['schema_matches_replay'])
        self.assertEqual(result['error_type'],'Inconclusive')

    def test_guard_exception_diagnostics_do_not_expose_private_content(self):
        def unavailable(binding,reserve,count):raise RuntimeError('PRIVATE_SCHEMA_DIAGNOSTIC')
        result,calls,_=self.run_comparison(guards={'source':unavailable})
        self.assertEqual(calls,[]);self.assertIsNone(result['schema_matches_replay'])
        self.assertEqual(result['error_type'],'RuntimeError')
        self.assertNotIn('PRIVATE_SCHEMA_DIAGNOSTIC',str(result))


if __name__=='__main__':unittest.main()
