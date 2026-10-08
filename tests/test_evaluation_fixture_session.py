"""Real authenticated mutation headers and sanitization of malformed tokens."""
from evaluation.identity_observer import PASSWORD, Session
from evaluation.verdicts import Inconclusive
from test_evaluation_identity_observer import LoopbackFixture


class FixtureSessionTest(LoopbackFixture):
    def login(self):
        session=Session(self.url,lambda reserve:True,5)
        value=session.request('POST','/auth/login',200,
                              dict(username='alpha-admin',password=PASSWORD))
        session.csrf=value['csrf_token']
        return session

    def test_all_authenticated_mutation_methods_send_session_bound_csrf(self):
        session=self.login()
        for method in ('POST','PUT','PATCH','DELETE'):
            with self.subTest(method=method):
                body=dict(roles=['auditor'])
                value=session.request(method,'/test-mutation',200,body)
                self.assertEqual(value,dict(method=method,body=body))
        session.request('POST','/auth/logout',204)
        self.assertEqual(self.sessions,{})

    def test_missing_or_different_token_cannot_mutate_with_a_valid_cookie(self):
        session=self.login()
        for token in (None,'wrong-but-safe-token'):
            session.csrf=token
            with self.subTest(token=token),self.assertRaises(Inconclusive):
                session.request('PUT','/test-mutation',200,dict(roles=['auditor']))

    def test_invalid_outbound_header_value_never_leaks_token_in_exception(self):
        session=self.login()
        session.csrf='synthetic-private-token-must-not-leak\nInjected: value'
        for method in ('POST','PUT','PATCH','DELETE'):
            with self.subTest(method=method),self.assertRaises(Inconclusive) as caught:
                session.request(method,'/test-mutation',200,dict(roles=['auditor']))
            self.assertNotIn('synthetic-private-token',str(caught.exception))
        self.assertEqual(self.requests,[('POST','/api/v1/auth/login')])

    def test_nonstring_token_or_invalid_missing_resource_mode_refuse_before_send(self):
        session=self.login()
        session.csrf=True
        with self.assertRaises(ValueError):session.request('PUT','/test-mutation',200,{})
        with self.assertRaises(ValueError):session.request('POST','/test-mutation',200,{},missing_ok=True)
        self.assertEqual(self.requests,[('POST','/api/v1/auth/login')])
