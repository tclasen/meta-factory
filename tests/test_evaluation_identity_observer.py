"""Actual loopback HTTP observations of the independently specified fixture."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from evaluation.identity_observer import USERS, observe_default_fixture
from evaluation.verdicts import Inconclusive


class LoopbackFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name).resolve()
        (self.project / 'ops').mkdir()
        self.manifest = dict(tenants={name:str(uuid.uuid4()) for name in ('alpha','beta')},
                             users={name:str(uuid.uuid4()) for name in USERS})
        self.path = self.project / 'ops/fixture-ids.json'
        self.path.write_text(json.dumps(self.manifest))
        self.fault = None
        self.requests = []
        self.sessions = {}
        self.roles = copy.deepcopy(USERS)
        self.case = None
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def answer(self, status, value=None):
                raw = b'' if value is None else json.dumps(value).encode()
                self.send_response(status)
                if getattr(self, 'cookie', None):
                    self.send_header('Set-Cookie', self.cookie)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def do_POST(self):
                fixture.requests.append(('POST',self.path))
                if self.path == '/api/v1/auth/login':
                    data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    if fixture.fault == 'redirect':
                        self.send_response(302)
                        self.send_header('Location',fixture.url+'/credential-leak')
                        self.send_header('Content-Length','0')
                        self.end_headers()
                        return
                    fixture.assertEqual(set(data),{'username','password'})
                    fixture.assertEqual(data['password'],'Fixture-only-2026!')
                    token = uuid.uuid4().hex
                    fixture.sessions[token] = data['username']
                    self.cookie = 'fixture='+token+'; Path=/; HttpOnly; SameSite=Strict'
                    self.answer(200,{'csrf_token':token})
                elif self.path == '/api/v1/auth/logout':
                    token = self.headers.get('Cookie','').removeprefix('fixture=')
                    fixture.assertEqual(self.headers['X-CSRF-Token'],token)
                    del fixture.sessions[token]
                    self.answer(204)
                else:
                    self.answer(404,{})
            def do_GET(self):
                fixture.requests.append(('GET',self.path))
                token = self.headers.get('Cookie','').removeprefix('fixture=')
                username = fixture.sessions.get(token)
                if username is None:
                    self.answer(401,{})
                    return
                if self.path == '/api/v1/auth/me':
                    roles = fixture.roles[username]
                    memberships = [dict(tenant_id=fixture.manifest['tenants'][name],roles=values)
                                   for name,values in roles.items()]
                    value = dict(id=fixture.manifest['users'][username],username=username,
                                 memberships=copy.deepcopy(memberships))
                    if fixture.fault == 'wrong-id':value['id']=str(uuid.uuid4())
                    elif fixture.fault == 'duplicate-roles':value['memberships'][0]['roles']*=2
                    elif fixture.fault == 'extra-role':value['memberships'][0]['roles'].append('administrator')
                    elif fixture.fault == 'missing-membership':value['memberships']=[]
                    elif fixture.fault == 'extra-membership':value['memberships'].append(copy.deepcopy(value['memberships'][0]))
                    elif fixture.fault == 'extra-field':value['token']='synthetic-not-a-real-secret'
                    elif fixture.fault == 'oversized':value['padding']='x'*65537
                    self.answer(200,value)
                    return
                name = next(name for name,identity in fixture.manifest['tenants'].items()
                            if '/'+identity+'/' in self.path)
                if '/memberships?' in self.path:
                    items = [dict(user_id=fixture.manifest['users'][user],username=user,roles=values[name])
                             for user,values in fixture.roles.items() if name in values]
                    value = dict(items=items,total=len(items),limit=100,offset=0)
                    if fixture.fault == 'extra-member':
                        value['items'].append(dict(user_id=str(uuid.uuid4()),username='unexpected',roles=['analyst']))
                        value['total']+=1
                    elif fixture.fault == 'boolean-limit':value['limit']=True
                    elif fixture.fault == 'persisted-role-mismatch':value['items'][0]['roles']=['administrator']
                    self.answer(200,value)
                elif '/cases?' in self.path:
                    value = dict(items=[],total=0,limit=1,offset=0)
                    if fixture.fault == 'nonempty':value.update(items=[{'id':str(uuid.uuid4())}],total=1)
                    elif fixture.fault == 'boolean-total':value['total']=False
                    self.answer(200,value)
                elif '/cases/' in self.path:
                    if fixture.fault == 'case-forbidden': self.answer(403, {'private':'must-not-be-logged'})
                    else: self.answer(200 if fixture.case is not None else 404, fixture.case)
        self.server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.url = 'http://127.0.0.1:'+str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join,2)
        self.addCleanup(self.server.shutdown)

class IdentityObserverTest(LoopbackFixture):
    def observe(self, **options):
        return observe_default_fixture(self.project,self.url,
            lifetime_check=options.pop('lifetime_check',lambda reserve:True), **options)

    def test_live_cookie_authenticated_reads_crosscheck_every_identity_and_logout(self):
        with patch.dict('os.environ',{'HTTP_PROXY':'http://127.0.0.1:1','http_proxy':'http://127.0.0.1:1'}):
            target, observation = self.observe()
        self.assertEqual(target['tenants'],self.manifest['tenants'])
        self.assertEqual(len(target['accounts']),9)
        self.assertEqual({u['username'] for u in observation['identities']['users']},set(USERS))
        self.assertEqual(observation['membership_counts'],{'alpha':6,'beta':4})
        self.assertEqual(observation['case_counts'],{'alpha':0,'beta':0})
        self.assertEqual(self.sessions,{})
        self.assertEqual(sum(path=='/api/v1/auth/logout' for _,path in self.requests),9)
        self.assertNotIn('csrf_token',json.dumps(observation))
        self.assertNotIn('password',json.dumps(observation))

    def test_distinct_entity_kinds_may_use_the_same_uuid(self):
        self.manifest['users']['alpha-analyst']=self.manifest['tenants']['alpha']
        self.path.write_text(json.dumps(self.manifest))
        target, observation = self.observe()
        self.assertEqual(len(observation['identities']['users']),9)

    def test_live_mismatches_cannot_construct_a_trusted_target(self):
        for fault in ('wrong-id','duplicate-roles','extra-role','missing-membership',
                      'extra-membership','extra-field','oversized','extra-member',
                      'boolean-limit','persisted-role-mismatch','nonempty','boolean-total'):
            with self.subTest(fault=fault):
                self.fault=fault
                with self.assertRaises(AssertionError):self.observe()

    def test_redirect_does_not_forward_credentials_or_follow_another_endpoint(self):
        self.fault='redirect'
        with self.assertRaises(Inconclusive):self.observe()
        self.assertEqual(self.requests,[('POST','/api/v1/auth/login')])

    def test_manifest_symlink_duplicate_keys_or_duplicate_ids_refuse_before_login(self):
        raw=self.path.read_text()
        for mode in ('symlink','duplicate-key','duplicate-id','unknown-user'):
            value=copy.deepcopy(self.manifest)
            if mode=='symlink':
                other=self.project/'outside.json';other.write_text(raw)
                self.path.unlink();self.path.symlink_to(other)
            elif mode=='duplicate-key':self.path.write_text('{"tenants":{},"tenants":{},"users":{}}')
            elif mode=='duplicate-id':
                value['users']['alpha-reviewer']=value['users']['alpha-analyst']
                self.path.write_text(json.dumps(value))
            else:
                value['users']['unreviewed']=str(uuid.uuid4());self.path.write_text(json.dumps(value))
            with self.subTest(mode=mode), self.assertRaises(Inconclusive):self.observe()
            self.path.unlink();self.path.write_text(raw)
        self.assertEqual(self.requests,[])

    def test_origin_and_lifetime_refuse_before_credentials_leave_memory(self):
        for url in ('https://127.0.0.1:1234','http://localhost:1234',
                    'http://127.0.0.1:1234/path','http://127.0.0.1:1234?token=x',
                    'http://user@127.0.0.1:1234','http://127.0.0.1:80'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                observe_default_fixture(self.project,url,lifetime_check=lambda reserve:True)
        with self.assertRaises(Inconclusive):self.observe(lifetime_check=lambda reserve:False)
        self.assertEqual(self.requests,[])

    def test_lifetime_is_rechecked_after_an_actual_network_response(self):
        def check(reserve):
            return len(self.requests)==0
        with self.assertRaises(Inconclusive):self.observe(lifetime_check=check)
        self.assertEqual(self.requests,[('POST','/api/v1/auth/login')])
