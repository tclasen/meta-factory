"""Private catalog validation and drift controls; native SQL checked separately."""
import copy
import json
import unittest

from evaluation.schema_catalog import SchemaCatalogReader, catalog_sql


BINDING = dict(schema='public',schema_oid=2200,database_name='fixture',operator_user='operator',operator_session_user='operator')


def observation():
    return dict(database_name='fixture',current_user='operator',session_user='operator',schema_oid=2200,
                server_version_num=170006,table_count=1,column_count=1,unsupported_count=0,oversized=False,extensions=[],
                tables=[dict(name='records',persistence='p',access_method='heap',row_security=False,
                    force_row_security=False,replica_identity='d',options=None,
                    columns=[dict(position=1,name='id',type='integer',not_null=True,identity='',generated='',
                                  collation=None,default='private-definition-control')],constraints=[],indexes=[])])


class SchemaCatalogTest(unittest.TestCase):
    def read(self,value):
        return SchemaCatalogReader(lambda *args,**kwargs:value,BINDING)()

    def test_supported_catalog_is_hashed_without_raw_definitions_or_migration_claim(self):
        result=self.read(observation())
        self.assertEqual(result['outcome'],'schema_catalog_observed')
        self.assertEqual(result['table_count'],1);self.assertEqual(result['column_count'],1)
        self.assertNotIn('private-definition-control',json.dumps(result))
        self.assertFalse(result['migration_current_verified']);self.assertFalse(result['data_verified'])
        self.assertFalse(result['privileges_verified'])

    def test_schema_database_role_version_count_and_missing_identity_refuse(self):
        for key,value in [('schema_oid',2201),('database_name','wrong'),('current_user','runtime'),
                          ('session_user','runtime'),('server_version_num',180000),('server_version_num',150000),
                          ('schema_oid',True),('schema_oid','2200'),('table_count',65),('column_count',0),('unsupported_count',1),
                          ('oversized',True),('tables',None)]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                altered=observation();altered[key]=value;self.read(altered)
        altered=observation();del altered['extensions']
        with self.assertRaises(ValueError):self.read(altered)

    def test_definition_and_constraint_index_flags_change_digest(self):
        initial=self.read(observation())['catalog_sha256']
        for kind in ('column','constraint','index','extension'):
            altered=observation();table=altered['tables'][0]
            if kind=='column':table['columns'][0]['not_null']=False
            if kind=='constraint':table['constraints']=[dict(name='positive',definition='CHECK ((id > 0))',validated=True,deferrable=False,deferred=False)]
            if kind=='index':table['indexes']=[dict(name='records_idx',definition='CREATE INDEX records_idx ON public.records USING btree (id)',valid=False,ready=True,live=True,replica_identity=False,clustered=False,options=None)]
            if kind=='extension':altered['extensions']=[dict(name='pgcrypto',version='1.3')]
            with self.subTest(kind=kind):self.assertNotEqual(initial,self.read(altered)['catalog_sha256'])

    def test_nested_missing_fields_duplicates_and_count_disagreement_refuse(self):
        for change in ('missing','duplicate','count','bool','huge','unsupported-am','bad-extension'):
            altered=observation();table=altered['tables'][0]
            if change=='missing':del table['columns'][0]['default']
            if change=='duplicate':table['columns'].append(copy.deepcopy(table['columns'][0]));altered['column_count']=2
            if change=='count':altered['column_count']=2
            if change=='bool':table['row_security']=1
            if change=='huge':table['columns'][0]['default']='x'*8193
            if change=='unsupported-am':table['access_method']='custom'
            if change=='bad-extension':altered['extensions']=[dict(name='pgcrypto',version=None)]
            with self.subTest(change=change),self.assertRaises(ValueError):self.read(altered)

    def test_relation_order_and_schema_mapping_are_bound(self):
        altered=observation();altered['tables']*=2;altered['table_count']=2;altered['column_count']=2
        with self.assertRaises(ValueError):self.read(altered)
        binding=copy.deepcopy(BINDING);reader=SchemaCatalogReader(lambda *args,**kwargs:observation(),binding)
        binding['schema_oid']=9999;self.assertEqual(reader()['outcome'],'schema_catalog_observed')
        with self.assertRaises(ValueError):catalog_sql(dict(BINDING,schema_oid=True))


if __name__=='__main__':unittest.main()
