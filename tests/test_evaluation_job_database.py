"""Durable job mappings fail closed before granting normalized observations."""
import copy
import unittest
from unittest.mock import Mock

from evaluation.job_database import AUDIT_FIELDS, JOB_FIELDS, JobDatabaseReader, job_read_sql

IDENTITY = '00000000-0000-0000-0000-000000000001'


def binding():
    def relation(name, fields, oid):
        return dict(schema='public', table=name, table_oid=oid,
                    fields={field: dict(column=field, path=[]) for field in fields})
    return dict(jobs=relation('jobs', JOB_FIELDS, 100), audit=relation('audit', AUDIT_FIELDS, 101),
                database_name='fixture', operator_user='reader', operator_session_user='reader')


class JobDatabaseTest(unittest.TestCase):
    def setUp(self):
        self.binding = binding()
        self.row = dict(export_id=IDENTITY, status='running', processing_attempts=4,
                        active_lease=True, lease_fingerprint='a'*64, completion_events=2)
        self.value = dict(database_name='fixture', current_user='reader', session_user='reader',
                          job_relation_oid=100, audit_relation_oid=101, jobs=[self.row])
        self.transport = Mock(side_effect=lambda *args, **kwargs: copy.deepcopy(self.value))
        self.reader = JobDatabaseReader(self.transport, self.binding)

    def test_normalized_projection_and_immutable_mapping(self):
        self.binding['jobs']['table_oid'] = 999
        self.row['lease_token'] = 'private'
        observation = self.reader(IDENTITY, timeout=15)
        self.assertEqual(observation['processing_attempts'], 4)
        self.assertEqual(observation['completion_events'], 2)
        self.assertNotIn('lease_token', observation)
        self.assertNotIn('published_artifacts', observation)
        args, kwargs = self.transport.call_args
        self.assertEqual(args[0], 'operator')
        self.assertEqual(kwargs['timeout'], 15)
        self.assertIn('BEGIN READ ONLY', args[1])
        self.assertIn('100::oid', args[1])

    def test_expired_claim_fingerprint_survives_normalized_projection(self):
        self.row['active_lease'] = False
        observation = self.reader(IDENTITY, timeout=15)
        self.assertEqual(observation['lease_fingerprint'], 'a'*64)
        self.assertFalse(observation['active_lease'])
        self.row['lease_fingerprint'] = None
        self.assertIsNone(self.reader(IDENTITY, timeout=15)['lease_fingerprint'])

    def test_explicit_token_only_lease_keeps_private_claim_projection(self):
        selected = binding()
        selected['jobs']['fields']['lease_owner'] = None
        reader = JobDatabaseReader(self.transport, selected)
        self.assertTrue(reader(IDENTITY, timeout=15)['active_lease'])
        query = self.transport.call_args.args[1]
        self.assertIn('NULL::text AS "lease_owner"', query)
        self.assertNotIn("NULLIF(lease_owner,'') IS NOT NULL", query)
        self.assertIn("NULLIF(lease_token,'') IS NOT NULL", query)
        self.assertIn('lease_expires_at::timestamptz > CURRENT_TIMESTAMP', query)
        self.assertIn('pg_catalog.sha256', query)
        self.assertIn('100::oid', query)
        self.assertIn('101::oid', query)

    def test_only_explicit_owner_absence_is_supported(self):
        for relation in ('jobs', 'audit'):
            for field in binding()[relation]['fields']:
                if field == 'lease_owner':
                    continue
                selected = binding()
                selected[relation]['fields'][field] = None
                with self.subTest(relation=relation, field=field), self.assertRaises(ValueError):
                    JobDatabaseReader(self.transport, selected)

    def test_both_relations_database_and_roles_must_match(self):
        for field in ('database_name', 'current_user', 'session_user', 'job_relation_oid', 'audit_relation_oid'):
            previous = self.value[field]
            self.value[field] = True if isinstance(previous, int) else 'different'
            with self.subTest(field=field), self.assertRaises(ValueError): self.reader(IDENTITY, timeout=15)
            self.value[field] = previous

    def test_missing_duplicate_or_mismatched_jobs_are_inconclusive(self):
        for rows in ([], [self.row, self.row], [None], [dict(self.row, export_id='wrong')]):
            self.value['jobs'] = rows
            with self.assertRaises(ValueError): self.reader(IDENTITY, timeout=15)

    def test_invalid_identity_refused_before_transport(self):
        with self.assertRaises(ValueError): self.reader('not-a-uuid', timeout=15)
        self.transport.assert_not_called()

    def test_complete_physical_mapping_and_positive_oids_required(self):
        for mutate in (lambda b:b['jobs'].update(table_oid=True),
                       lambda b:b['audit'].update(table_oid=0),
                       lambda b:b['jobs']['fields'].pop('lease_token'),
                       lambda b:b['jobs']['fields']['lease_owner'].update(path='arbitrary-sql'),
                       lambda b:b.update(secret='private')):
            selected = binding(); mutate(selected)
            with self.assertRaises(ValueError): JobDatabaseReader(self.transport, selected)
