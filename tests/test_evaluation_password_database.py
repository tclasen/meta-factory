"""Private credential reads reject incorrect scope and independently bound identity."""
import copy
import unittest
from unittest.mock import Mock

from evaluation.password_database import PasswordDatabaseReader,password_read_sql


def binding():
    return dict(accounts=dict(schema='public',table='accounts',table_oid=100,
        fields={key:dict(column=key,path=[]) for key in ('identity','encoded_hash')}),
        database_name='fixture',operator_user='reader',operator_session_user='reader')


class PasswordDatabaseTest(unittest.TestCase):
    def setUp(self):
        self.binding=binding()
        self.value=dict(database_name='fixture',current_user='reader',session_user='reader',
            account_relation_oid=100,truncated=False,accounts=[dict(identity='a',encoded_hash='private-a'),dict(identity='b',encoded_hash='private-b')])
        self.transport=Mock(side_effect=lambda *args,**kwargs:copy.deepcopy(self.value))
        self.reader=PasswordDatabaseReader(self.transport,self.binding)

    def test_private_scope_and_original_binding(self):
        self.binding['accounts']['table_oid']=999
        self.assertEqual(self.reader(['b','a']),{'a':'private-a','b':'private-b'})
        args,kwargs=self.transport.call_args
        self.assertEqual(args[0],'operator')
        self.assertEqual(kwargs['timeout'],15)
        self.assertNotIn('private-a',args[1])
        self.assertNotIn('private-b',args[1])

    def test_database_roles_relation_and_truncation_must_match(self):
        for key,new in [('database_name','other'),('current_user','other'),('session_user','other'),
                        ('account_relation_oid',True),('account_relation_oid',101),('truncated',True),('truncated',0)]:
            with self.subTest(key=key,new=new):
                old=self.value[key];self.value[key]=new
                with self.assertRaises(ValueError):self.reader(['a','b'])
                self.value[key]=old

    def test_missing_duplicate_unknown_or_extra_accounts_refused(self):
        good=copy.deepcopy(self.value['accounts'])
        for rows in ([],good[:1],[good[0],good[0]],[dict(good[0],identity='other'),good[1]],good+[good[0]],
                     [dict(representation_unavailable=True),good[1]],[dict(good[0],private='extra'),good[1]]):
            with self.subTest(rows=len(rows)):
                self.value['accounts']=rows
                with self.assertRaises(ValueError):self.reader(['a','b'])
        self.value['accounts']=good

    def test_invalid_and_oversized_hashes_never_return(self):
        for value in (None,1,'','x'*4097,'é'*2049):
            self.value['accounts'][0]['encoded_hash']=value
            with self.assertRaisesRegex(ValueError,'Private password observation identity or scope unavailable'):
                self.reader(['a','b'])

    def test_extra_transport_fields_refused(self):
        self.value['private_data']='must-not-return'
        with self.assertRaises(ValueError):self.reader(['a','b'])

    def test_invalid_scope_refused_before_transport(self):
        for scope in ([],['a','a'],['a',None],[''],['a\x00'],['é'*129],['x']*65,'a'):
            with self.assertRaises(ValueError):self.reader(scope)
        self.transport.assert_not_called()

    def test_complete_mapping_required_before_any_transport(self):
        for change in (lambda b:b['accounts'].update(table_oid=True),lambda b:b['accounts'].update(table_oid=0),
                       lambda b:b['accounts']['fields'].pop('encoded_hash'),
                       lambda b:b['accounts']['fields']['encoded_hash'].update(path='arbitrary-sql'),
                       lambda b:b.update(operator_user=''),lambda b:b.update(extra='private')):
            value=binding();change(value)
            with self.assertRaises(ValueError):PasswordDatabaseReader(self.transport,value)
        self.transport.assert_not_called()

    def test_nested_mapping_and_quoted_names_are_expressions_not_statements(self):
        value=binding();value['accounts']['table']='accounts"; SELECT malicious; --'
        value['accounts']['fields']['encoded_hash']=dict(column='payload',path=['credentials',"hash'); SELECT malicious; --"])
        query=password_read_sql(value,["operator'); SELECT malicious; --"])
        self.assertIn('"accounts""; SELECT malicious; --"',query)
        self.assertIn("E'operator''); SELECT malicious; --'",query)
        self.assertIn("E'hash''); SELECT malicious; --'",query)
        self.assertIn('BEGIN READ ONLY',query)
        self.assertIn('LOCK TABLE',query)
        self.assertIn('IS DISTINCT FROM 100::oid',query)
        self.assertIn("SET LOCAL search_path = pg_catalog",query)
        self.assertIn("relkind IN (''r'',''p'')",query)


if __name__=='__main__':unittest.main()
