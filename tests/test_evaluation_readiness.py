"""Readiness must not accept a broad or unreviewed effective network policy."""

import unittest

from evaluation.readiness import effective_tcp_policy


class ReadinessTest(unittest.TestCase):
    def snapshot(self, resources, **overrides):
        rule = {'status': 'active', 'scope': 'sandbox:fixture', 'resource_type': 'network',
                'decision': 'allow', 'actions': ['net:connect:tcp'], 'resources': resources}
        rule.update(overrides)
        return {'rules': [rule]}

    def test_exact_effective_destinations_only(self):
        approved = ['registry.npmjs.org:443']
        self.assertTrue(effective_tcp_policy(self.snapshot(approved), 'fixture', approved))
        for resources in [['**'], ['*:443'], ['registry.npmjs.org:443', 'unreviewed.invalid:443'], []]:
            self.assertFalse(effective_tcp_policy(self.snapshot(resources), 'fixture', approved))

    def test_global_allow_all_or_foreign_scope_cannot_pass(self):
        approved = ['registry.npmjs.org:443']
        snapshot = self.snapshot(approved)
        snapshot['rules'].extend(self.snapshot(['**'], scope='global')['rules'])
        self.assertFalse(effective_tcp_policy(snapshot, 'fixture', approved))
        self.assertFalse(effective_tcp_policy(self.snapshot(approved, scope='sandbox:other'), 'fixture', approved))
        self.assertFalse(effective_tcp_policy({}, 'fixture', approved))
