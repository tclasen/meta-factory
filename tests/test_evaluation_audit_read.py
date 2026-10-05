"""Operator audit mappings must remain bounded and non-executable."""
import copy
import unittest
import uuid
from evaluation.database_probe import AUDIT_FIELDS, audit_read_sql


class AuditReadTest(unittest.TestCase):
    def setUp(self):
        self.fields = {key: {'column': 'payload', 'path': [key]} for key in AUDIT_FIELDS}
        self.correlations = [str(uuid.uuid4())]

    def query(self, **changes):
        values = dict(schema='public',table='audit_events',table_oid=123,
                      fields=self.fields,correlations=self.correlations)
        values.update(changes)
        return audit_read_sql(**values)

    def test_invalid_relation_and_collection_bounds_refused(self):
        for changes in ({'table_oid':True},{'table_oid':0},{'limit':0},{'limit':129},
                        {'limit':True},{'correlations':[]},{'correlations':['not-a-uuid']},
                        {'correlations':self.correlations*2},
                        {'correlations':[str(uuid.uuid4()) for _ in range(33)]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):self.query(**changes)

    def test_complete_mapping_and_no_executable_expressions(self):
        for fields in ({}, dict(self.fields, unknown={}),
                       dict(self.fields, id={'sql':'current_user'}),
                       dict(self.fields, id={'column':'id','path':'$.id'}),
                       dict(self.fields, id={'column':'id','path':['x']*9}),
                       dict(self.fields, id={'column':'id','path':['\0']})):
            with self.subTest(fields=fields), self.assertRaises(ValueError):self.query(fields=fields)

    def test_forbidden_canaries_are_bounded_nonempty_strings(self):
        for values in ('secret',[''],[None],['\0'],['x'*4097],['x']*33,['x'*4096]*5):
            with self.subTest(values=type(values)), self.assertRaises(ValueError):
                self.query(forbidden_values=values)

    def test_mapping_is_not_mutated(self):
        original=copy.deepcopy(self.fields)
        source=self.query(forbidden_values=['private newline\n"\\canary'])
        self.assertEqual(self.fields,original)
        self.assertLessEqual(len(source.encode()),256*1024)
        self.assertTrue(source.startswith('BEGIN READ ONLY;'))


if __name__=='__main__':unittest.main()
