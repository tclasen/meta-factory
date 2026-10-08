"""Live preservation snapshots retain changes instead of restoring defaults."""
import copy
import time
from types import SimpleNamespace
import uuid

from evaluation.bootstrap import repeat_bootstrap
from evaluation.bootstrap_observer import observe_repeat_fixture
from evaluation.evidence import Attempt
from evaluation.identity_observer import observe_default_fixture
from evaluation.verdicts import Inconclusive
from test_evaluation_identity_observer import LoopbackFixture


class BootstrapObserverTest(LoopbackFixture):
    def setUp(self):
        super().setUp()
        _, initial = observe_default_fixture(self.project, self.url,
                                              lifetime_check=lambda reserve: True)
        self.identities = initial['identities']
        self.case_id = str(uuid.uuid4())
        self.case = dict(id=self.case_id, tenant_id=self.manifest['tenants']['alpha'],
            title='Independent repeat canary', description='Keep this persisted value',
            severity='high', status='open', assignee_id=None,
            created_by=self.manifest['users']['alpha-analyst'],
            created_at='2026-10-07T00:00:00Z', updated_at='2026-10-07T00:00:00Z', version=1)
        self.roles['alpha-dual']['alpha'] = ['auditor']
        self.requests.clear()

    def observe(self, **options):
        return observe_repeat_fixture(self.url, self.identities, self.case_id,
            lifetime_check=options.pop('lifetime_check', lambda reserve: True), **options)

    def test_changed_roles_and_full_case_are_independently_observed(self):
        result = self.observe()
        self.assertEqual(result['case'], self.case)
        dual = next(user for user in result['identities']['users'] if user['username']=='alpha-dual')
        self.assertEqual(dual['memberships'][0]['roles'], ['auditor'])
        self.assertEqual(self.sessions, {})
        self.assertNotIn('password', str(result))
        self.assertNotIn('csrf_token', str(result))
        self.assertEqual(sum(path=='/api/v1/auth/logout' for _,path in self.requests),9)

    def test_case_missing_is_observed_but_other_http_errors_are_inconclusive(self):
        self.case = None
        self.assertIsNone(self.observe()['case'])
        for fault in ('case-forbidden', 'redirect'):
            self.fault = fault
            with self.subTest(fault=fault), self.assertRaises(Inconclusive) as caught: self.observe()
            self.assertNotIn('must-not-be-logged', str(caught.exception))

    def test_role_removal_and_identity_replacement_are_not_hidden_by_defaults(self):
        self.roles['alpha-dual'] = {}
        self.manifest['users']['beta-reviewer'] = str(uuid.uuid4())
        result = self.observe()
        dual = next(user for user in result['identities']['users'] if user['username']=='alpha-dual')
        self.assertEqual(dual['memberships'], [])
        beta = next(user for user in result['identities']['users'] if user['username']=='beta-reviewer')
        initial = next(user for user in self.identities['users'] if user['username']=='beta-reviewer')
        self.assertNotEqual(beta['id'], initial['id'])

    def test_inconsistent_persisted_memberships_and_unknown_roles_refuse(self):
        for fault in ('extra-member', 'persisted-role-mismatch', 'boolean-limit', 'duplicate-roles', 'extra-membership'):
            self.fault = fault
            with self.subTest(fault=fault), self.assertRaises(Inconclusive): self.observe()
        self.fault = None
        self.roles['alpha-dual']['alpha'] = ['root']
        with self.assertRaises(Inconclusive): self.observe()

    def test_lifetime_and_missing_admin_observation_refuse(self):
        with self.assertRaises(Inconclusive): self.observe(lifetime_check=lambda reserve:False)
        self.assertEqual(self.requests, [])
        self.roles['alpha-admin'] = {'alpha':['analyst']}
        with self.assertRaises(Inconclusive): self.observe()

    def test_repeat_bootstrap_detects_case_and_membership_reset_using_live_snapshots(self):
        baseline = self.observe()
        for mode in ('preserve', 'delete', 'edit', 'reset-roles'):
            self.case = copy.deepcopy(baseline['case'])
            self.roles['alpha-dual']['alpha'] = ['auditor']
            box = SimpleNamespace(name='factory-eval-grader-0123456789abcdef',
                                  project=self.project, stopped=False, creation_attempted=True)
            box.exec_argv=lambda command:['sbx','exec','-w',str(self.project),box.name]+command
            guard_dir = self.project / ('guard-'+mode);guard_dir.mkdir()
            guard = SimpleNamespace(directory=guard_dir,process=SimpleNamespace(poll=lambda:None))
            def command(*args, **options):
                if mode=='delete': self.case=None
                elif mode=='edit': self.case['version']=2
                elif mode=='reset-roles': self.roles['alpha-dual']['alpha']=['analyst','reviewer']
                return dict(outcome='passed',exit_code=0)
            def verify(before, after, expected):
                self.assertEqual(before, baseline)
                self.assertEqual(after, baseline)
                self.assertEqual(before['case'], expected)
            with self.subTest(mode=mode), Attempt(self.project/('logs-'+mode),{}) as attempt:
                result=repeat_bootstrap(attempt,box,guard,
                    observe=lambda *args,**kwargs:self.observe(), verify=verify,
                    expected_case=baseline['case'], source_check=lambda reserve:True,
                    monotonic_deadline=time.monotonic()+60,wall_deadline=time.time()+60,
                    command_runner=command)
                self.assertEqual(result['verdict'], 'pass' if mode=='preserve' else 'fail')
                self.assertEqual(result['abort_suite'], mode!='preserve')

    def test_invalid_initial_identity_configuration_refuses_before_login(self):
        for change in ('duplicate', 'missing', 'malformed'):
            initial = copy.deepcopy(self.identities)
            if change=='duplicate': initial['users'][0]['id']=initial['users'][1]['id']
            elif change=='missing': initial['tenants'].pop()
            else: initial['users'][0]['id']='not-a-uuid'
            with self.subTest(change=change), self.assertRaises(ValueError):
                observe_repeat_fixture(self.url, initial, self.case_id,
                                       lifetime_check=lambda reserve:True)
        self.assertEqual(self.requests, [])
