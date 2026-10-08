"""Private ordinary-table catalog snapshots for independently replayed migrations.

No candidate code, migration SQL or row data is executed by this collector.
Unsupported schema objects refuse comparison rather than silently disappearing.
Extension member definitions, grants and physical storage are outside its scope.
"""
import copy
import hashlib
import json

from .database_probe import identifier, sql_literal


def validate_catalog(tables, extensions, column_count):
    def names(entries):
        values = []
        for entry in entries:
            if not isinstance(entry, dict):raise ValueError('Catalog entry unavailable')
            identifier(entry.get('name'));values.append(entry['name'])
        if values != sorted(set(values), key=lambda v:v.encode('utf-8')):
            raise ValueError('Catalog ordering or uniqueness unavailable')
    def flags(entry, fields):
        if any(type(entry[field]) is not bool for field in fields):raise ValueError('Catalog flags unavailable')
    def options(value):
        if value is not None and (not isinstance(value, list) or len(value)>64
                or any(not isinstance(v, str) or not v or len(v.encode())>4096 for v in value)):
            raise ValueError('Catalog options unavailable')
    names(tables);names(extensions);columns = constraints = indexes = 0
    for extension in extensions:
        if set(extension)!={'name','version'} or not isinstance(extension['version'],str) or not 1<=len(extension['version'])<=128:
            raise ValueError('Catalog extension version unavailable')
    for table in tables:
        if (set(table)!={'name','persistence','access_method','row_security','force_row_security',
                        'replica_identity','options','columns','constraints','indexes'}
                or table['persistence'] not in ('p','u') or table['access_method']!='heap'
                or table['replica_identity'] not in ('d','n','f','i')
                or not all(isinstance(table[field],list) for field in ('columns','constraints','indexes'))):
            raise ValueError('Supported ordinary table projection unavailable')
        flags(table, ('row_security','force_row_security'));options(table['options'])
        if not 1<=len(table['columns'])<=1600:raise ValueError('Column scope unavailable')
        positions = [];column_names = set()
        for column in table['columns']:
            if (not isinstance(column,dict) or set(column)!={'position','name','type','not_null','identity','generated','collation','default'}
                    or type(column['position']) is not int or not 1<=column['position']<=1600
                    or not isinstance(column['type'],str) or not 1<=len(column['type'].encode())<=256
                    or column['identity'] not in ('','a','d') or column['generated'] not in ('','s')
                    or column['collation'] is not None and (not isinstance(column['collation'],str) or not 1<=len(column['collation'].encode())<=256)
                    or column['default'] is not None and (not isinstance(column['default'],str) or len(column['default'].encode())>8192)):
                raise ValueError('Column catalog projection unavailable')
            identifier(column['name']);flags(column, ('not_null',));positions.append(column['position'])
            if column['name'] in column_names:raise ValueError('Duplicate catalog column')
            column_names.add(column['name'])
        if positions!=sorted(set(positions)):raise ValueError('Catalog column order unavailable')
        for kind in ('constraints','indexes'):
            names(table[kind])
            for entry in table[kind]:
                required = ({'name','definition','validated','deferrable','deferred'} if kind=='constraints' else
                            {'name','definition','valid','ready','live','replica_identity','clustered','options'})
                if (set(entry)!=required or not isinstance(entry['definition'],str)
                        or not 1<=len(entry['definition'].encode())<=8192):
                    raise ValueError('Catalog definition unavailable')
                flags(entry, ('validated','deferrable','deferred') if kind=='constraints' else
                      ('valid','ready','live','replica_identity','clustered'))
                if kind=='indexes':options(entry['options'])
        columns+=len(table['columns']);constraints+=len(table['constraints']);indexes+=len(table['indexes'])
    if columns!=column_count or constraints>4096 or indexes>4096:
        raise ValueError('Catalog counts or bounds unavailable')


def catalog_sql(binding):
    if (not isinstance(binding, dict) or set(binding) != {
            'schema', 'schema_oid', 'database_name', 'operator_user', 'operator_session_user'}
            or type(binding['schema_oid']) is not int or not 0 < binding['schema_oid'] <= 4294967295):
        raise ValueError('Independently observed database/schema binding required')
    for key in ('schema', 'database_name', 'operator_user', 'operator_session_user'):identifier(binding[key])
    # Catalog functions reconstruct DDL; raw expressions stay in private transport.
    # pg_depend extension membership is excluded explicitly and extension versions
    # are retained. This does not attest installed extension code or its objects.
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL client_min_messages = error;
WITH namespace AS MATERIALIZED (
 SELECT oid FROM pg_catalog.pg_namespace WHERE nspname=%s
), relations AS MATERIALIZED (
 SELECT c.* FROM pg_catalog.pg_class c JOIN namespace n ON n.oid=c.relnamespace
 WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
  WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=c.oid AND d.deptype='e')
), tables AS MATERIALIZED (
 SELECT * FROM relations WHERE relkind='r' ORDER BY relname COLLATE "C" LIMIT 65
), projected AS MATERIALIZED (
 SELECT pg_catalog.jsonb_build_object(
  'name',t.relname,'persistence',t.relpersistence,'access_method',am.amname,
  'row_security',t.relrowsecurity,'force_row_security',t.relforcerowsecurity,
  'replica_identity',t.relreplident,'options',t.reloptions,
  'columns',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
   'position',a.attnum,'name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),
   'not_null',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,
   'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE cn.nspname||'.'||co.collname END,
   'default',pg_catalog.pg_get_expr(ad.adbin,ad.adrelid,false)) ORDER BY a.attnum)
   FROM pg_catalog.pg_attribute a
   LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
   LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
   LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
   WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb),
  'constraints',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
   'name',c.conname,'definition',pg_catalog.pg_get_constraintdef(c.oid,false),
   'validated',c.convalidated,'deferrable',c.condeferrable,'deferred',c.condeferred)
   ORDER BY c.conname COLLATE "C") FROM pg_catalog.pg_constraint c WHERE c.conrelid=t.oid),'[]'::jsonb),
  'indexes',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
   'name',ic.relname,'definition',pg_catalog.pg_get_indexdef(i.indexrelid,0,false),
   'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,
   'replica_identity',i.indisreplident,'clustered',i.indisclustered,'options',ic.reloptions)
   ORDER BY ic.relname COLLATE "C") FROM pg_catalog.pg_index i
   JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid WHERE i.indrelid=t.oid),'[]'::jsonb)
 ) AS entry FROM tables t LEFT JOIN pg_catalog.pg_am am ON am.oid=t.relam
), catalog AS MATERIALIZED (
 SELECT COALESCE(pg_catalog.jsonb_agg(entry ORDER BY entry->>'name' COLLATE "C"),'[]'::jsonb) AS entries
 FROM projected
), other_objects AS (
 SELECT oid,'pg_catalog.pg_collation'::regclass AS classid FROM pg_catalog.pg_collation
  WHERE collnamespace IN (SELECT oid FROM namespace)
 UNION ALL SELECT oid,'pg_catalog.pg_operator'::regclass FROM pg_catalog.pg_operator
  WHERE oprnamespace IN (SELECT oid FROM namespace)
 UNION ALL SELECT oid,'pg_catalog.pg_opclass'::regclass FROM pg_catalog.pg_opclass
  WHERE opcnamespace IN (SELECT oid FROM namespace)
 UNION ALL SELECT oid,'pg_catalog.pg_opfamily'::regclass FROM pg_catalog.pg_opfamily
  WHERE opfnamespace IN (SELECT oid FROM namespace)
 UNION ALL SELECT oid,'pg_catalog.pg_conversion'::regclass FROM pg_catalog.pg_conversion
  WHERE connamespace IN (SELECT oid FROM namespace)
 UNION ALL SELECT oid,'pg_catalog.pg_ts_parser'::regclass FROM pg_catalog.pg_ts_parser
  WHERE prsnamespace IN (SELECT oid FROM namespace)
 UNION ALL SELECT oid,'pg_catalog.pg_ts_template'::regclass FROM pg_catalog.pg_ts_template
  WHERE tmplnamespace IN (SELECT oid FROM namespace)
 UNION ALL SELECT oid,'pg_catalog.pg_ts_dict'::regclass FROM pg_catalog.pg_ts_dict
  WHERE dictnamespace IN (SELECT oid FROM namespace)
 UNION ALL SELECT oid,'pg_catalog.pg_ts_config'::regclass FROM pg_catalog.pg_ts_config
  WHERE cfgnamespace IN (SELECT oid FROM namespace)
), unsupported AS (
 SELECT
 (SELECT count(*) FROM relations c WHERE c.relkind NOT IN ('r','i') OR c.relispartition OR c.reloftype<>0) +
 (SELECT count(*) FROM pg_catalog.pg_inherits i JOIN relations c ON c.oid=i.inhrelid OR c.oid=i.inhparent) +
 (SELECT count(*) FROM pg_catalog.pg_trigger g JOIN relations c ON c.oid=g.tgrelid WHERE NOT g.tgisinternal) +
 (SELECT count(*) FROM pg_catalog.pg_rewrite r JOIN relations c ON c.oid=r.ev_class) +
 (SELECT count(*) FROM pg_catalog.pg_policy p JOIN relations c ON c.oid=p.polrelid) +
 (SELECT count(*) FROM pg_catalog.pg_proc p JOIN namespace n ON n.oid=p.pronamespace
  WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
   WHERE d.classid='pg_catalog.pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')) +
 (SELECT count(*) FROM pg_catalog.pg_type y JOIN namespace n ON n.oid=y.typnamespace
  WHERE y.typrelid=0 AND y.typelem=0 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
   WHERE d.classid='pg_catalog.pg_type'::regclass AND d.objid=y.oid AND d.deptype='e')) +
 (SELECT count(*) FROM pg_catalog.pg_attribute a JOIN relations c ON c.oid=a.attrelid
  JOIN pg_catalog.pg_type y ON y.oid=a.atttypid JOIN pg_catalog.pg_namespace n ON n.oid=y.typnamespace
  WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND n.nspname<>'pg_catalog')
 + (SELECT count(*) FROM other_objects o WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
  WHERE d.classid=o.classid AND d.objid=o.oid AND d.deptype='e')) AS count
)
SELECT pg_catalog.json_build_object(
 'database_name',current_database(),'current_user',current_user,'session_user',session_user,
 'schema_oid',(SELECT oid::bigint FROM namespace),'server_version_num',current_setting('server_version_num')::integer,
 'table_count',(SELECT count(*) FROM relations WHERE relkind='r'),
 'column_count',(SELECT count(*) FROM pg_catalog.pg_attribute a JOIN tables t ON t.oid=a.attrelid
  WHERE a.attnum>0 AND NOT a.attisdropped),
 'unsupported_count',(SELECT count FROM unsupported),
 'oversized',(SELECT pg_catalog.octet_length(entries::text)>524288 FROM catalog),
 'tables',CASE WHEN (SELECT pg_catalog.octet_length(entries::text)>524288 FROM catalog)
  THEN NULL ELSE (SELECT entries FROM catalog) END,
 'extensions',COALESCE((SELECT json_agg(json_build_object('name',e.extname,'version',e.extversion)
  ORDER BY e.extname COLLATE "C") FROM pg_catalog.pg_extension e JOIN namespace n ON n.oid=e.extnamespace),'[]'::json)
);
COMMIT;
""" % sql_literal(binding['schema'])


class SchemaCatalogReader:
    """Transport binds live database/credentials; caller binds source and scope.

    Returned catalog digest covers ordinary table columns/defaults/constraints/
    indexes, selected table flags and extension versions. Not migration history,
    grants/owners, extension implementation, arbitrary schema semantics or data.
    Compare only independently replayed baselines on the same server version.
    """
    def __init__(self, transport, binding):
        if not callable(transport):raise ValueError('Trusted private catalog transport required')
        self.binding = copy.deepcopy(binding)
        self.sql = catalog_sql(self.binding)
        self.transport = transport

    def __call__(self, *, timeout=15):
        value = self.transport('operator', self.sql, timeout=timeout)
        fields = {'database_name','current_user','session_user','schema_oid','server_version_num',
                  'table_count','column_count','unsupported_count','oversized','tables','extensions'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['database_name'] != self.binding['database_name']
                or value['current_user'] != self.binding['operator_user']
                or value['session_user'] != self.binding['operator_session_user']
                or type(value['schema_oid']) is not int or value['schema_oid'] != self.binding['schema_oid']
                or type(value['server_version_num']) is not int or not 160000 <= value['server_version_num'] < 180000
                or type(value['table_count']) is not int or not 1 <= value['table_count'] <= 64
                or type(value['column_count']) is not int or not 1 <= value['column_count'] <= 4096
                or type(value['unsupported_count']) is not int or value['unsupported_count'] != 0
                or value['oversized'] is not False or not isinstance(value['tables'], list)
                or len(value['tables']) != value['table_count'] or not isinstance(value['extensions'], list)
                or len(value['extensions']) > 64):
            raise ValueError('Complete supported catalog identity unavailable')
        # Private catalog definitions never become diagnostics or public receipts.
        validate_catalog(value['tables'], value['extensions'], value['column_count'])
        normalized = dict(server_version_num=value['server_version_num'], tables=value['tables'],
                          extensions=value['extensions'])
        raw = json.dumps(normalized, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > 524288:raise ValueError('Private catalog projection limit')
        return dict(outcome='schema_catalog_observed', catalog_sha256=hashlib.sha256(raw).hexdigest(),
                    table_count=value['table_count'], column_count=value['column_count'],
                    extension_count=len(value['extensions']), server_version_num=value['server_version_num'],
                    migration_current_verified=False, data_verified=False, privileges_verified=False,
                    limits='Bound ordinary-table catalog only; independent migration replay/source binding '
                           'and other schema objects, extension code, grants and data remain separate.')
