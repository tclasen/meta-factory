"""Pinned transitive closure and extras/marker controls over private metadata."""
import copy
import json
import unittest

from packaging.markers import default_environment

from evaluation.python_dependencies import inspect_python_dependencies


def report():
    environment=dict(default_environment(),python_version='3.12',python_full_version='3.12.9',
                     implementation_name='cpython',implementation_version='3.12.9',sys_platform='linux',platform_system='Linux')
    def dist(name,version,dependencies=(),extras=()):
        return dict(metadata=dict(name=name,version=version,requires_dist=list(dependencies),provides_extra=list(extras),requires_python='>=3.11'))
    return dict(version='1',pip_version='25.0',environment=environment,installed=[
        dist('root','1.0',['child>=2', 'optional==3 ; extra == "fast"', 'windows-only>=1 ; sys_platform == "win32"'],['fast']),
        dist('child','2.0'),dist('optional','3.0'),dist('unmapped-base-tool','4.0')])


LOCK=b'root==1.0\nchild==2.0\noptional==3.0\n'
ROOTS=b'root[fast]>=1.0\n'


class PythonDependencyTest(unittest.TestCase):
    def inspect(self,locked=LOCK,declared=ROOTS,observed=None):
        return inspect_python_dependencies(locked,declared,report() if observed is None else observed)

    def test_pins_cover_actual_metadata_closure_with_extra_and_platform_marker(self):
        value=self.inspect();self.assertTrue(value['declared_closure_pinned'])
        self.assertEqual(value['required_distribution_count'],3);self.assertEqual(value['unmapped_installed_count'],1)
        for flag in ('artifact_hashes_verified','application_imports_verified','build_consumption_verified','installed_environment_bound'):
            self.assertFalse(value[flag])
        self.assertNotIn('unmapped-base-tool',json.dumps(value))

    def test_unlocked_transitive_range_wildcard_and_multiple_specifiers_are_false(self):
        for lock in (b'root==1.0\noptional==3.0',LOCK.replace(b'child==2.0',b'child>=2'),
                     LOCK.replace(b'child==2.0',b'child==2.*'),LOCK.replace(b'child==2.0',b'child>=2,<3')):
            with self.subTest(lock=lock):
                value=self.inspect(locked=lock);self.assertFalse(value['declared_closure_pinned'])
                self.assertEqual(value['unlocked_dependency_count'],1)

    def test_missing_installed_package_pin_version_and_dependency_conflict_are_false(self):
        missing=report();missing['installed']=missing['installed'][1:]
        self.assertFalse(self.inspect(observed=missing)['declared_closure_pinned'])
        mismatch=self.inspect(locked=LOCK.replace(b'child==2.0',b'child==2.1'))
        self.assertFalse(mismatch['declared_closure_pinned']);self.assertEqual(mismatch['version_mismatch_count'],1)
        conflict=report();conflict['installed'][0]['metadata']['requires_dist'][0]='child<2'
        self.assertEqual(self.inspect(observed=conflict)['constraint_conflict_count'],1)

    def test_extras_activate_late_across_a_cycle_and_ordinary_names_normalize(self):
        observed=report();observed['installed'][0]['metadata']['requires_dist']=['child[feature]>=2']
        observed['installed'][1]['metadata'].update(provides_extra=['feature'],requires_dist=['root>=1','optional==3 ; extra == "feature"'])
        value=self.inspect(declared=b'root==1.0',observed=observed)
        self.assertTrue(value['declared_closure_pinned']);self.assertEqual(value['required_distribution_count'],3)
        # Process child before root activates its extra. The new context must
        # revisit child and discover the optional package missing from the lock.
        late=self.inspect(locked=b'child==2.0\nroot==1.0',declared=b'root==1.0',observed=observed)
        self.assertFalse(late['declared_closure_pinned']);self.assertEqual(late['unlocked_dependency_count'],1)
        observed['installed'][0]['metadata']['name']='Root_Package'
        observed['installed'][1]['metadata']['requires_dist'][0]='root.package>=1'
        value=self.inspect(locked=LOCK.replace(b'root==',b'root-package=='),declared=b'root.package==1.0',observed=observed)
        self.assertTrue(value['declared_closure_pinned'])

    def test_declared_and_lock_extras_missing_metadata_and_requires_python_are_checked(self):
        observed=report();observed['installed'][0]['metadata']['provides_extra']=[]
        self.assertEqual(self.inspect(observed=observed)['unavailable_extra_count'],1)
        observed=report();observed['installed'][1]['metadata']['requires_python']='>=3.13'
        self.assertEqual(self.inspect(observed=observed)['python_conflict_count'],1)
        value=self.inspect(locked=LOCK.replace(b'root==',b'root[fast]=='),declared=b'root==1.0')
        self.assertTrue(value['declared_closure_pinned'])

    def test_inactive_platform_pin_and_optional_requirements_are_not_silently_required(self):
        value=self.inspect(locked=LOCK+b'windows-only==1.0 ; sys_platform == "win32"\n')
        self.assertTrue(value['declared_closure_pinned']);self.assertEqual(value['locked_version_count'],3)
        value=self.inspect(locked=b'root==1.0\nchild==2.0',declared=b'root==1.0')
        self.assertTrue(value['declared_closure_pinned']);self.assertEqual(value['unmapped_installed_count'],2)

    def test_hash_annotations_comments_and_continuations_do_not_invent_artifact_proof(self):
        lock=b'# ordinary lock\nroot==1.0 \\\n --hash=sha256:'+b'a'*64+b'\nchild==2.0 # pinned\noptional==3.0\n'
        value=self.inspect(locked=lock);self.assertTrue(value['declared_closure_pinned'])
        self.assertFalse(value['artifact_hashes_verified'])

    def test_exact_pin_with_additional_constraints_is_still_a_fixed_version(self):
        value=self.inspect(locked=LOCK.replace(b'child==2.0',b'child==2.0,<3'))
        self.assertTrue(value['declared_closure_pinned'])
        value=self.inspect(locked=LOCK.replace(b'child==2.0',b'child==2.0,!=2.0'))
        self.assertFalse(value['declared_closure_pinned']);self.assertEqual(value['constraint_conflict_count'],1)
        self.assertIsNone(self.inspect(locked=LOCK.replace(b'child==2.0',b'child===2.0'))['declared_closure_pinned'])

    def test_unknown_report_layout_duplicate_distribution_and_environment_conflict_are_unknown(self):
        observations=[]
        unknown=report();unknown['version']='2';observations.append(unknown)
        duplicate=report();duplicate['installed'].append(copy.deepcopy(duplicate['installed'][0]));observations.append(duplicate)
        inconsistent=report();inconsistent['environment']['python_version']='3.11';observations.append(inconsistent)
        missing=report();del missing['environment']['sys_platform'];observations.append(missing)
        for observed in observations:
            with self.subTest(observed=observed):self.assertIsNone(self.inspect(observed=observed)['declared_closure_pinned'])

    def test_directives_urls_nonpositive_extra_markers_and_malformed_input_are_unknown(self):
        for lock in (b'-r other.txt',b'root @ https://private-user:PRIVATE_SECRET@example.invalid/x',
                     b'root==1.0 ; extra != "fast"',b'root==1.0\nroot==1.0',b'root==1.0 \\',b'\xff'):
            value=self.inspect(locked=lock);self.assertIsNone(value['declared_closure_pinned'])
            self.assertNotIn('PRIVATE_SECRET',str(value));self.assertNotIn('example.invalid',str(value))

    def test_all_active_locked_rows_seed_closure_including_nonroot_dependencies(self):
        observed=report();observed['installed'][2]['metadata']['requires_dist']=['undisclosed-child>=1']
        value=self.inspect(declared=b'root==1.0',observed=observed)
        self.assertFalse(value['declared_closure_pinned']);self.assertEqual(value['unlocked_dependency_count'],1)
        self.assertEqual(value['missing_distribution_count'],1)


if __name__=='__main__':unittest.main()
