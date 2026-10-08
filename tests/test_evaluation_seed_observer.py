"""Alternate synthetic identities are verified without default-name assumptions."""
import copy
import json
import uuid

from evaluation.identity_observer import observe_seed_fixture
from evaluation.verdicts import Inconclusive
from test_evaluation_identity_observer import LoopbackFixture


class SeedObserverTest(LoopbackFixture):
    def setUp(self):
        super().setUp()
        aliases={'alpha':'north', 'beta':'south'}
        names={name:'seed-'+str(index)+'-'+uuid.uuid4().hex[:8]
               for index,name in enumerate(self.roles)}
        self.roles={names[name]:{aliases[tenant]:roles for tenant,roles in memberships.items()}
                    for name,memberships in self.roles.items()}
        self.passwords={name:'Synthetic-'+uuid.uuid4().hex for name in names.values()}
        self.manifest=dict(tenants={aliases[name]:value for name,value in self.manifest['tenants'].items()},
                           users={names[name]:value for name,value in self.manifest['users'].items()})
        self.path.write_text(json.dumps(self.manifest))

    def observe(self, **options):
        return observe_seed_fixture(self.project,self.url,self.roles,self.passwords,
            lifetime_check=options.pop('lifetime_check',lambda reserve:True),**options)

    def test_live_alternate_names_passwords_and_tenant_aliases(self):
        declared, value=self.observe()
        self.assertEqual(declared,self.manifest)
        self.assertEqual(value['membership_counts'],{'north':6,'south':4})
        self.assertEqual(value['case_counts'],{'north':0,'south':0})
        self.assertEqual({user['username'] for user in value['identities']['users']},set(self.roles))
        self.assertEqual(self.sessions,{})
        for password in self.passwords.values():self.assertNotIn(password,str((declared,value)))

    def test_expected_unassigned_user_is_verified_through_live_login(self):
        self.roles['seed-unassigned']={}
        self.passwords['seed-unassigned']='Independent-only-2026!'
        self.manifest['users']['seed-unassigned']=str(uuid.uuid4())
        self.path.write_text(json.dumps(self.manifest))
        _, value=self.observe()
        user=next(user for user in value['identities']['users'] if user['username']=='seed-unassigned')
        self.assertEqual(user['memberships'],[])
        self.assertEqual(user['id'],self.manifest['users']['seed-unassigned'])

    def test_roles_compare_as_sets_without_changing_operator_input(self):
        expected=copy.deepcopy(self.roles)
        for memberships in expected.values():
            for roles in memberships.values():roles.reverse()
        original=copy.deepcopy(expected)
        _, value=observe_seed_fixture(self.project,self.url,expected,self.passwords,
                                     lifetime_check=lambda reserve:True)
        self.assertEqual(expected,original)
        self.assertEqual(len(value['identities']['users']),9)

    def test_default_ids_role_errors_and_persisted_extra_users_cannot_pass(self):
        for fault in ('wrong-id','extra-role','extra-member','persisted-role-mismatch','nonempty'):
            self.fault=fault
            with self.subTest(fault=fault),self.assertRaises(AssertionError):self.observe()

    def test_manifest_roster_and_aliases_must_match_independent_input(self):
        original=copy.deepcopy(self.manifest)
        for fault in ('missing-user','extra-user','different-alias'):
            value=copy.deepcopy(original)
            if fault=='missing-user':value['users'].pop(next(iter(value['users'])))
            elif fault=='extra-user':value['users']['builder-selected']=str(uuid.uuid4())
            else:value['tenants']['builder-selected']=value['tenants'].pop('north')
            self.path.write_text(json.dumps(value))
            with self.subTest(fault=fault),self.assertRaises(Inconclusive):self.observe()
        self.assertEqual(self.requests,[])

    def test_invalid_operator_configuration_refuses_before_credentials_are_sent(self):
        for fault in ('missing-password','short-password','unknown-role','duplicate-role',
                      'no-admin','no-reader','invalid-username','too-many-users'):
            roles=copy.deepcopy(self.roles);passwords=copy.deepcopy(self.passwords)
            user=next(iter(roles))
            if fault=='missing-password':passwords.pop(user)
            elif fault=='short-password':passwords[user]='short'
            elif fault=='unknown-role':roles[user]['north']=['root']
            elif fault=='duplicate-role':roles[user]['north']=['analyst','analyst']
            elif fault in ('no-admin','no-reader'):
                remove={'administrator'} if fault=='no-admin' else {'analyst','reviewer'}
                for memberships in roles.values():
                    if 'north' in memberships:
                        memberships['north']=[r for r in memberships['north'] if r not in remove]
                        if not memberships['north']:del memberships['north']
            elif fault=='invalid-username':roles['UPPERCASE']=roles.pop(user);passwords['UPPERCASE']=passwords.pop(user)
            else:
                for index in range(101):roles['seed-extra-'+str(index)]={};passwords['seed-extra-'+str(index)]='Independent-only-2026!'
            with self.subTest(fault=fault),self.assertRaises(ValueError):
                observe_seed_fixture(self.project,self.url,roles,passwords,lifetime_check=lambda reserve:True)
        self.assertEqual(self.requests,[])

    def test_lifetime_loss_stops_alternate_fixture_observations(self):
        with self.assertRaises(Inconclusive):self.observe(lifetime_check=lambda reserve:len(self.requests)==0)
        self.assertEqual(len(self.requests),1)
