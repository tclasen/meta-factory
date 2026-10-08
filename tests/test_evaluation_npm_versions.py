"""Version inventory cannot masquerade as native npm consistency or installation."""
import base64
import json
import unittest

from evaluation.npm_versions import inspect_npm_versions


def inputs():
    manifest=dict(name='fixture',version='1.0.0',dependencies={'root':'^1.0.0'})
    lock=dict(lockfileVersion=3,packages={'':dict(manifest),
        'node_modules/root':dict(version='1.2.3',resolved='https://registry.npmjs.org/root/-/root-1.2.3.tgz',
            integrity='sha512-'+base64.b64encode(b'a'*64).decode(),dependencies={'child':'^2.0.0'}),
        'node_modules/root/node_modules/@scope/child':dict(version='2.3.4-beta.1+build.2',optional=True,dev=True,peer=True)})
    return manifest,lock


class NpmVersionsTest(unittest.TestCase):
    def observe(self,mutate=None):
        manifest,lock=inputs()
        if mutate:mutate(manifest,lock)
        return inspect_npm_versions(json.dumps(manifest).encode(),json.dumps(lock).encode())

    def test_all_registry_entries_including_nested_optional_peer_versions_are_counted(self):
        value=self.observe();self.assertTrue(value['recorded_versions_fixed'])
        self.assertEqual(value['package_count'],2);self.assertEqual(value['optional_package_count'],1)
        self.assertEqual(value['dev_package_count'],1);self.assertEqual(value['peer_package_count'],1)
        self.assertEqual(value['integrity_annotation_count'],1)
        self.assertNotIn('registry.npmjs.org',str(value));self.assertNotIn('@scope',str(value))
        for field in ('native_consistency_verified','installed_environment_bound','artifact_integrity_verified','build_consumption_verified'):
            self.assertFalse(value[field])

    def test_range_wildcard_missing_or_noncanonical_versions_are_observed_unfixed(self):
        for version in ('^1.0.0','1.*','1.0','01.0.0','1.0.0-01',None):
            with self.subTest(version=version):
                value=self.observe(lambda manifest,lock:lock['packages']['node_modules/root'].update(version=version))
                self.assertFalse(value['recorded_versions_fixed']);self.assertEqual(value['unfixed_version_count'],1)

    def test_manifest_changes_do_not_get_a_fake_semver_consistency_verdict(self):
        value=self.observe(lambda manifest,lock:manifest['dependencies'].update(root='^9.0.0'))
        self.assertTrue(value['recorded_versions_fixed']);self.assertFalse(value['native_consistency_verified'])

    def test_workspace_link_git_and_credential_resolutions_are_unknown(self):
        mutations=[lambda manifest,lock:manifest.update(workspaces=['packages/*']),
            lambda manifest,lock:lock.update(lockfileVersion=2),
            lambda manifest,lock:lock['packages']['node_modules/root'].update(link=True),
            lambda manifest,lock:lock['packages']['node_modules/root'].update(resolved='git+https://example.invalid/a#abcdef'),
            lambda manifest,lock:lock['packages']['node_modules/root'].update(resolved='https://user:PRIVATE_SECRET@example.invalid/x')]
        for mutate in mutations:
            value=self.observe(mutate);self.assertIsNone(value['recorded_versions_fixed'])
            self.assertNotIn('PRIVATE_SECRET',str(value))

    def test_duplicate_keys_paths_integrity_flags_and_bounds_refuse(self):
        manifest,lock=inputs()
        value=inspect_npm_versions(b'{"dependencies":{},"dependencies":{}}',json.dumps(lock).encode())
        self.assertIsNone(value['recorded_versions_fixed'])
        for mutate in (lambda manifest,lock:lock['packages'].update({'node_modules/../x':dict(version='1.0.0')}),
                       lambda manifest,lock:lock['packages']['node_modules/root'].update(integrity='sha512-invalid'),
                       lambda manifest,lock:lock['packages']['node_modules/root'].update(integrity='   '),
                       lambda manifest,lock:lock['packages']['node_modules/root'].update(optional=1),
                       lambda manifest,lock:lock['packages']['node_modules/root'].update(dependencies=[])):
            self.assertIsNone(self.observe(mutate)['recorded_versions_fixed'])
        self.assertIsNone(inspect_npm_versions(b'x'*(4*1024*1024+1),b'{}')['recorded_versions_fixed'])

    def test_absent_integrity_annotations_do_not_impose_an_undisclosed_requirement(self):
        value=self.observe(lambda manifest,lock:lock['packages']['node_modules/root'].pop('integrity'))
        self.assertTrue(value['recorded_versions_fixed']);self.assertEqual(value['integrity_annotation_count'],0)


if __name__=='__main__':unittest.main()
