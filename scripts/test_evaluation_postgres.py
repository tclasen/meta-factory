#!/usr/bin/env python3
"""Disposable sandbox-local PostgreSQL metadata preflight; no host/model calls."""
import argparse
import platform
import json
from pathlib import Path
import signal
import sys
import tempfile
import traceback
import uuid
REPO=Path(__file__).resolve().parents[1];sys.path.insert(0,str(REPO))
from evaluation.evidence import Attempt,collect,atomic_json
from evaluation.grading import sha256
from evaluation import database_probe as probe
PROBE=Path(probe.__file__)
IMAGE='postgres@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3'
SETUP='''
CREATE ROLE migration NOLOGIN;
CREATE ROLE safe LOGIN;
CREATE ROLE columnwriter LOGIN;
CREATE ROLE deleter LOGIN;
CREATE ROLE switched LOGIN NOINHERIT;
CREATE ROLE noset LOGIN NOINHERIT;
CREATE ROLE inherited LOGIN;
CREATE ROLE rls_writer LOGIN;
CREATE ROLE updateonly LOGIN;
CREATE ROLE deleteonly LOGIN;
CREATE TABLE public.audit_events(id integer PRIMARY KEY, message text);
ALTER TABLE public.audit_events OWNER TO migration;
INSERT INTO public.audit_events VALUES (1, 'Synthetic first row'), (2, 'Synthetic second row');
GRANT UPDATE(message) ON public.audit_events TO updateonly;
GRANT DELETE ON public.audit_events TO deleteonly;
GRANT SELECT, INSERT ON public.audit_events TO safe, columnwriter, deleter;
GRANT UPDATE(message) ON public.audit_events TO columnwriter;
GRANT DELETE ON public.audit_events TO deleter;
GRANT migration TO switched WITH SET TRUE, INHERIT FALSE;
GRANT migration TO noset WITH SET FALSE, INHERIT FALSE;
GRANT columnwriter TO inherited WITH INHERIT TRUE, SET FALSE;
CREATE TABLE public.rls_audit(id integer PRIMARY KEY, message text);
ALTER TABLE public.rls_audit OWNER TO migration;
INSERT INTO public.rls_audit VALUES (1, 'Synthetic row');
GRANT SELECT, UPDATE ON public.rls_audit TO rls_writer;
ALTER TABLE public.rls_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rls_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY read_rows ON public.rls_audit FOR SELECT TO rls_writer USING (true);
CREATE SCHEMA "odd'schema";
CREATE TABLE "odd'schema"."odd""table"(id integer);
ALTER TABLE "odd'schema"."odd""table" OWNER TO migration;
GRANT USAGE ON SCHEMA "odd'schema" TO safe;
'''


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    base=REPO/'.factory-planning/postgres-preflight-logs';base.mkdir(parents=True,exist_ok=True)
    directory=Path(tempfile.mkdtemp(prefix='run-',dir=base));directory.rmdir()
    name='factory-postgres-probe-'+uuid.uuid4().hex[:12]
    print('Logs:',directory,'\nContainer:',name,flush=True)
    print('Caches the pinned image if absent; creates only this network-disabled, unpublished local container with tmpfs data and a 240-second internal lifetime; synthetic roles only. Removes it on completion.',flush=True)
    report={'outcome':'failed','container':name,'manual_cleanup':['docker','rm','-f',name],
            'limits':'PostgreSQL17 catalog and rollback-only mutation fixture only. Synthetic atomicity only; not real application role mapping, password hashing or acceptance.'}
    with Attempt(directory,{'kind':'local_postgres_privileges','image':IMAGE,'probe_sha256':sha256(PROBE),'script_sha256':sha256(__file__)}) as attempt:
        attempt.transition('preflight');created=False
        def check(label,command,timeout=30,required=True):
            result=collect(attempt,label,command,cwd=REPO,timeout=timeout)
            if required and result['outcome']!='passed':raise RuntimeError(label+' failed; inspect retained logs')
            return result
        def sql(label,role,source):
            check(label,['docker','exec',name,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',role,'-d','postgres','-c',source])
            return (directory/label/'stdout.log').read_text().strip()
        try:
            check('revision',['git','rev-parse','HEAD']);check('python',[sys.executable,'--version'])
            check('worktree',['git','status','--porcelain'])
            if platform.system() != 'Linux':
                raise RuntimeError('Run this preflight inside the Linux sbx, not directly on the host Mac')
            check('docker-version',['docker','version','--format','{{.Server.Version}}'])
            cached=check('image-cache',['docker','image','inspect',IMAGE,'--format','{{json .RepoDigests}}'],required=False)
            if cached['outcome']!='passed':
                check('image-pull',['docker','pull',IMAGE],timeout=180)
            check('image',['docker','image','inspect',IMAGE,'--format','{{json .RepoDigests}}'])
            # Mark ownership before creation; an interrupted CLI may still create it.
            created=True
            check('create',['docker','run','-d','--name',name,'--init','--network','none','--cpus','2','--memory','512m',
                '--tmpfs','/var/lib/postgresql/data:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
                '--entrypoint','timeout',IMAGE,'--signal=TERM','--kill-after=10s','240s','docker-entrypoint.sh','postgres'])
            check('ready',['docker','exec',name,'sh','-c',
                'i=0; until pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; do i=$((i+1)); [ "$i" -lt 100 ] || exit 1; sleep 0.2; done'],timeout=30)
            sql('setup','postgres',SETUP)
            observed={}
            for role in ('safe','columnwriter','deleter','switched','noset','inherited','postgres','rls_writer'):
                table='rls_audit' if role=='rls_writer' else 'audit_events'
                value=json.loads(sql('probe-'+role.replace('_','-'),role,probe.privilege_sql('public',table)))
                assert value['current_user']==role and value['session_user']==role and value['relation_found']
                observed[role]=value
            own=lambda role:next(v for v in observed[role]['reachable_roles'] if v['name']==role)
            assert not any(own('safe')[key] for key in ('owns_table','table_update','column_update','table_delete','table_truncate'))
            assert own('columnwriter')['column_update'] and not own('columnwriter')['table_update']
            assert own('deleter')['table_delete']
            assert any(v['name']=='migration' and v['owns_table'] for v in observed['switched']['reachable_roles'])
            assert [v['name'] for v in observed['noset']['reachable_roles']]==['noset']
            assert own('inherited')['column_update']
            assert own('postgres')['superuser'] and own('postgres')['table_delete']
            assert own('rls_writer')['table_update'] and observed['rls_writer']['force_row_security']
            # A catalog grant is not proof that RLS permits modifying a row.
            count=sql('rls-denied-write','rls_writer',"BEGIN; WITH changed AS (UPDATE public.rls_audit SET message='Should not persist' RETURNING id) SELECT count(*) FROM changed; ROLLBACK;")
            assert count=='0',count
            assert json.loads(sql('quoted-identifiers','safe',probe.privilege_sql("odd'schema",'odd"table')))['relation_found']
            assert not json.loads(sql('missing-table','safe',probe.privilege_sql('public','absent')))['relation_found']
            assert not json.loads(sql('injection-name','safe',probe.privilege_sql('public',"absent'; DROP TABLE audit_events; --")))['relation_found']
            assert json.loads(sql('table-retained','safe',probe.privilege_sql('public','audit_events')))['relation_found']
            mutations=[]
            def snapshot(label):
                return sql(label,'postgres',"SELECT json_build_object('rows',count(*),'digest',md5(coalesce(json_agg(a ORDER BY id)::text,''))) FROM public.audit_events a;")
            before=snapshot('mutation-baseline')
            variants=[('safe','update',None,'sql_rejected',None),
                      ('safe','delete',None,'sql_rejected',None),
                      ('columnwriter','update',None,'write_executed',2),
                      ('columnwriter','delete',None,'sql_rejected',None),
                      ('deleter','delete',None,'write_executed',2),
                      ('deleter','update',None,'sql_rejected',None),
                      ('switched','delete',None,'sql_rejected',None),
                      ('switched','delete','migration','write_executed',2),
                      ('switched','update','migration','write_executed',2),
                      ('inherited','update',None,'write_executed',2),
                      ('updateonly','update',None,'write_executed',2),
                      ('deleteonly','delete',None,'write_executed',2)]
            for index,(role,operation,assume,outcome,rows) in enumerate(variants):
                options={'column':'message','value':"Synthetic '\\ $body$ change"} if operation=='update' else {}
                result=json.loads(sql('mutation-'+str(index),role,probe.mutation_sql('public','audit_events',operation,assume_role=assume,**options)))
                assert result['outcome']==outcome,result
                assert result['session_user']==role and result['current_user']==(assume or role),result
                if rows is not None:assert result['rows']==rows,result
                else:assert result['sqlstate']=='42501',result
                assert snapshot('restore-'+str(index))==before,'Rollback did not restore rows'
                mutations.append(dict(result,operation=operation))
            rls=json.loads(sql('mutation-rls','rls_writer',probe.mutation_sql('public','rls_audit','update',column='message',value='Synthetic change')))
            assert rls['outcome']=='write_executed' and rls['rows']==0,rls
            assert sql('rls-unchanged','postgres',"SELECT count(*) FROM public.rls_audit WHERE id=1 AND message='Synthetic row';")=='1'
            missing=json.loads(sql('mutation-missing','safe',probe.mutation_sql('public','missing','delete')))
            assert missing['outcome']=='sql_rejected' and missing['sqlstate']=='42P01',missing
            # Check quoted names and literal escaping with nonstandard string mode.
            quoted=probe.mutation_sql("odd'schema",'odd"table','delete')
            assert json.loads(sql('mutation-quoted','postgres',quoted))['rows']==0
            unusual=probe.privilege_sql('public', "missing\\'; DROP TABLE audit_events; --")
            assert not json.loads(sql('nonstandard-literal','postgres',"SET standard_conforming_strings=off;"+unusual))['relation_found']
            assert snapshot('after-escaping')==before
            sql('trigger-fixtures','postgres',"""
                CREATE TABLE public.trigger_audit(id integer, message text);
                INSERT INTO public.trigger_audit VALUES (1, 'Synthetic retained row');
                GRANT UPDATE(message) ON public.trigger_audit TO updateonly;
                CREATE FUNCTION public.reject_audit_change() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE NOTICE 'Synthetic private audit row';
                    RAISE EXCEPTION 'Synthetic private audit row' USING ERRCODE='23514';
                END $$;
                CREATE TRIGGER audit_guard BEFORE UPDATE ON public.trigger_audit
                  FOR EACH ROW EXECUTE FUNCTION public.reject_audit_change();
                CREATE TABLE public.slow_audit(id integer, message text);
                INSERT INTO public.slow_audit VALUES (1, 'Synthetic retained row');
                GRANT UPDATE(message) ON public.slow_audit TO updateonly;
                CREATE FUNCTION public.delay_audit_change() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN PERFORM pg_sleep(10); RETURN NEW; END $$;
                CREATE TRIGGER audit_delay BEFORE UPDATE ON public.slow_audit
                  FOR EACH ROW EXECUTE FUNCTION public.delay_audit_change();
            """)
            for table,expected in [('trigger_audit','23514'),('slow_audit','57014')]:
                label=table.replace('_','-')
                value=json.loads(sql(label,'updateonly',probe.mutation_sql('public',table,'update',column='message',value='Synthetic change')))
                assert value['outcome']=='sql_rejected' and value['sqlstate']==expected,value
                assert 'Synthetic private audit row' not in (directory/label/'stderr.log').read_text()
                assert sql(label+'-unchanged','postgres',"SELECT count(*) FROM public."+table+" WHERE id=1 AND message='Synthetic retained row';")=='1'
                mutations.append(value)
            mutations.extend([rls,missing])
            # Concrete failure path: business write and required audit insert.
            sql('atomicity-setup','postgres',"""
                CREATE TABLE public.business_records(id integer PRIMARY KEY, message text);
                GRANT SELECT,INSERT ON public.business_records TO safe;
                ALTER TABLE public.audit_events ADD CONSTRAINT fixture_positive_id CHECK(id>0);
            """)
            def application_write(label,identity,atomic=True):
                statements=("INSERT INTO public.business_records VALUES (%d,'Synthetic business row');"
                            "INSERT INTO public.audit_events VALUES (%d,'Synthetic audit row');") % (identity,identity)
                if atomic:statements='BEGIN;'+statements+'COMMIT;'
                # Separate psql requests model a genuinely non-atomic implementation.
                if not atomic:
                    sql(label+'-business','safe',statements.split(';')[0]+';')
                    statements=statements.split(';')[1]+';'
                return check(label,['docker','exec',name,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
                                    '-U','safe','-d','postgres','-c',statements],required=False)
            assert application_write('atomicity-baseline',100)['outcome']=='passed'
            audit_before=snapshot('audit-before-fault')
            def business_snapshot(label):
                return sql(label,'postgres',"SELECT json_build_object('rows',count(*),'digest',md5(coalesce(json_agg(b ORDER BY id)::text,''))) FROM public.business_records b;")
            business_before=business_snapshot('business-before-fault')
            oid=int(observed['safe']['relation_oid']);gate_name='factory_audit_fault_'+uuid.uuid4().hex
            gate=json.loads(sql('audit-gate-install','postgres',probe.audit_insert_fault_sql('public','audit_events',oid,gate_name,action='install')))
            gate_oid=int(gate['constraint_oid'])
            assert gate['outcome']=='audit_gate_installed' and int(gate['table_oid'])==oid
            assert snapshot('audit-after-gate')==audit_before,'Installing gate changed existing rows'
            assert application_write('atomicity-rejected',101)['outcome']=='failed'
            assert business_snapshot('business-after-rejection')==business_before,'Atomic write leaked business state'
            assert snapshot('audit-after-rejection')==audit_before
            assert application_write('non-atomic-rejected',102,atomic=False)['outcome']=='failed'
            assert business_snapshot('non-atomic-detected')!=business_before,'Failed to detect separate commits'
            sql('remove-bad-fixture-write','postgres','DELETE FROM public.business_records WHERE id=102;')
            assert business_snapshot('business-restored')==business_before
            # A stale identity must never remove a similarly named object.
            stale=probe.audit_insert_fault_sql('public','audit_events',oid,gate_name,action='remove',constraint_oid=gate_oid+1)
            refused=check('stale-gate-refused',['docker','exec',name,'psql','-X','-q','-v','ON_ERROR_STOP=1','-U','postgres','-c',stale],required=False)
            assert refused['outcome']=='failed'
            assert application_write('gate-still-active',103)['outcome']=='failed'
            removed=json.loads(sql('audit-gate-remove','postgres',probe.audit_insert_fault_sql('public','audit_events',oid,gate_name,action='remove',constraint_oid=gate_oid)))
            assert removed['outcome']=='audit_gate_removed'
            assert application_write('atomicity-recovered',104)['outcome']=='passed'
            assert sql('unrelated-constraint-retained','postgres',"SELECT count(*) FROM pg_constraint WHERE conrelid='public.audit_events'::regclass AND conname='fixture_positive_id';")=='1'
            # Wrong table identity is rejected under the relation lock, before DDL.
            wrong=probe.audit_insert_fault_sql('public','audit_events',oid+1,'factory_audit_fault_'+uuid.uuid4().hex,action='install')
            assert check('wrong-table-refused',['docker','exec',name,'psql','-X','-q','-v','ON_ERROR_STOP=1','-U','postgres','-c',wrong],required=False)['outcome']=='failed'
            assert sql('faults-absent','postgres',"SELECT count(*) FROM pg_constraint WHERE conrelid='public.audit_events'::regclass AND conname LIKE 'factory_audit_fault_%';")=='0'
            atomic_json(directory/'audit-atomicity.json',{'outcome':'synthetic_atomicity_distinguished',
                'atomic_write_rolled_back':True,'non_atomic_write_detected':True,'restoration_verified':True,
                'stale_constraint_refused':True,'wrong_table_refused':True,'unrelated_constraint_retained':True})
            atomic_json(directory/'mutation-observations.json',mutations)
            atomic_json(directory/'observations.json',observed)
            report['outcome']='postgres_catalog_fixture_passed'
        except BaseException:
            (directory/'error.log').write_text(traceback.format_exc())
        finally:
            if created:
                check('database-logs',['docker','logs',name],required=False)
                check('remove',['docker','rm','-f',name],required=False)
                result=check('verify-removed',['docker','ps','-a','--filter','name=^/'+name+'$','--format','{{.Names}}'],required=False)
                report['container_removed']=result['outcome']=='passed' and not (directory/'verify-removed/stdout.log').read_text().strip()
                if not report['container_removed']:report['outcome']='cleanup_incomplete'
            attempt.transition('failed');attempt.finish(report)
            print('Outcome:',report['outcome'],'\nLogs:',directory,flush=True)
    return 0 if report['outcome']=='postgres_catalog_fixture_passed' else 1

if __name__=='__main__':
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    raise SystemExit(main())
