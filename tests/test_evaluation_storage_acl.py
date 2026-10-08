"""Adversarial ACL structure controls, without effective privacy inference."""
import unittest

from evaluation.storage_acl_semantics import ANONYMOUS_ID, classify_acl


def grant(kind='CanonicalUser', value='fixture-owner', permission='FULL_CONTROL'):
    field = 'URI' if kind == 'Group' else 'ID'
    return ('<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:type="' + kind + '"><' + field + '>' + value + '</' + field + '>'
            '</Grantee><Permission>' + permission + '</Permission></Grant>')


def acl(*grants, namespace='http://s3.amazonaws.com/doc/2006-03-01/'):
    return ('<AccessControlPolicy xmlns="' + namespace + '"><Owner><ID>fixture-owner</ID>'
            '</Owner><AccessControlList>' + ''.join(grants) +
            '</AccessControlList></AccessControlPolicy>').encode()


class StorageAclTest(unittest.TestCase):
    def test_specific_owner_and_service_grants_have_no_privacy_verdict(self):
        for namespace in ('', 'http://s3.amazonaws.com/doc/2006-03-01/'):
            result = classify_acl(200, acl(grant(), grant('Group',
                'http://acs.amazonaws.com/groups/s3/LogDelivery', 'WRITE'), namespace=namespace))
            self.assertEqual(result['classification'], 'no_broad_grant_in_supported_acl')
            self.assertEqual(result['grant_count'], 2)
            self.assertEqual(len(result['owner_sha256']), 64)
            self.assertNotIn('private', result)
            self.assertNotIn('fixture-owner', str(result))
        empty_names = acl(grant()).replace(b'</ID>', b'</ID><DisplayName/>')
        self.assertEqual(classify_acl(200, empty_names)['classification'],
                         'no_broad_grant_in_supported_acl')

    def test_public_groups_and_anonymous_canonical_user_are_broad(self):
        for kind, identity in [('Group', 'http://acs.amazonaws.com/groups/global/AllUsers'),
                               ('Group', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'),
                               ('CanonicalUser', ANONYMOUS_ID)]:
            for permission in ('READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'):
                with self.subTest(kind=kind, permission=permission):
                    result = classify_acl(200, acl(grant(), grant(kind, identity, permission)))
                    self.assertEqual(result['classification'], 'broad_acl_grant_observed')
                    self.assertEqual(result['broad_grant_count'], 1)

    def test_unknown_grantees_groups_permissions_prevent_complete_classification(self):
        for entry in (grant('AmazonCustomerByEmail'), grant('Group', 'https://unknown.invalid'),
                      grant(permission='UNKNOWN'), grant(value='contains whitespace'),
                      grant().replace('xsi:type=', 'unknown='),
                      grant().replace('<ID>', '<ID extra="1">')):
            with self.subTest(entry=entry):
                result = classify_acl(200, acl(grant('Group',
                    'http://acs.amazonaws.com/groups/global/AllUsers'), entry))
                self.assertEqual(result['classification'], 'inconclusive')
                self.assertEqual(result['unsupported_grant_count'], 1)
                self.assertEqual(result['broad_grant_count'], 1)

    def test_missing_duplicate_foreign_and_mixed_schema_are_inconclusive(self):
        source = acl(grant())
        malformed = [acl(grant(), namespace='https://foreign.invalid'), acl(),
                     source.replace(b'<ID>fixture-owner</ID>', b'<ID/>'),
                     source.replace(b'<Owner>', b'<Owner extra="1">'),
                     source.replace(b'</Owner>', b'</Owner><Owner><ID>second</ID></Owner>'),
                     source.replace(b'<Grant>', b'<Unknown>'),
                     source.replace(b'<ID>fixture-owner</ID>', b'<ID xmlns="">fixture-owner</ID>'),
                     source.replace(b'<Permission>', b'<Permission>unexpected<Unknown/>'),
                     source.replace(b'<AccessControlList>', b'<AccessControlList>unexpected'),
                     source.replace(b'</Owner>', b'<Unknown/></Owner>')]
        for raw in malformed:
            with self.subTest(raw=raw):
                self.assertEqual(classify_acl(200, raw)['classification'], 'inconclusive')

    def test_bounds_entities_encoding_and_unavailable_api(self):
        source = acl(grant())
        for status in (403, 404, 301, 500):
            self.assertEqual(classify_acl(status, source)['classification'], 'inconclusive')
        for raw in (b'x' * 65537, b'\xff', source.decode().encode('utf-16'),
                    b'<!DOCTYPE AccessControlPolicy>' + source,
                    b'<!ENTITY attack "value">' + source,
                    acl(*(grant() for _ in range(101))),
                    source.replace(b'<Owner>', b'<Owner>' + b'<Unknown/>' * 1024)):
            self.assertEqual(classify_acl(200, raw)['classification'], 'inconclusive')


if __name__ == '__main__':
    unittest.main()
