"""An installed-image archive is data, including executable startup hooks."""
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest

from evaluation.python_dependencies import inspect_python_dependencies
from evaluation.python_image_metadata import inspect_python_image_archive, MetadataUnavailable


def fixture(*, child=True, missing_metadata=False, duplicate_header=False, unsafe=False,
            legacy=False, hook=True, metadata_version='2.1'):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as archive:
        root=tarfile.TarInfo('site-packages');root.type=tarfile.DIRTYPE;archive.addfile(root)
        packages=[('pip','24.3.1',''),('factory_root','1.0','Requires-Dist: factory-child==2.0\n')]
        if child:packages.append(('factory_child','2.0',''))
        for name,version,requires in packages:
            folder='site-packages/'+name+'-'+version+'.dist-info'
            entry=tarfile.TarInfo(folder);entry.type=tarfile.DIRTYPE;archive.addfile(entry)
            if missing_metadata and name=='factory_root':continue
            body=('Metadata-Version: '+metadata_version+'\nName: '+name+'\nVersion: '+version+'\n'+requires+
                  ('Import-Name: factory_root\nImport-Namespace: factory_shared\n'
                   if metadata_version in ('2.5','2.6') and name=='factory_root' else '')+
                  ('Name: spoofed\n' if duplicate_header and name=='factory_root' else '')+'\nPrivate package description').encode()
            entry=tarfile.TarInfo(folder+'/METADATA');entry.size=len(body);archive.addfile(entry,io.BytesIO(body))
        if hook:
            body=b'import pathlib; pathlib.Path("/outside/executed").write_text("bad")'
            entry=tarfile.TarInfo('site-packages/candidate.pth');entry.size=len(body);archive.addfile(entry,io.BytesIO(body))
        if unsafe:
            entry=tarfile.TarInfo('site-packages/link');entry.type=tarfile.SYMTYPE;entry.linkname='/outside';archive.addfile(entry)
        if legacy:
            entry=tarfile.TarInfo('site-packages/unknown.egg-info');entry.size=1;archive.addfile(entry,io.BytesIO(b'x'))
    return stream.getvalue()


class PythonImageMetadataTest(unittest.TestCase):
    def inspect(self, raw):return inspect_python_image_archive(io.BytesIO(raw))

    def test_real_metadata_fields_and_extra_distribution_preserved_for_closure(self):
        value=self.inspect(fixture())
        result=inspect_python_dependencies(b'factory-root==1.0\nfactory-child==2.0\n',
                                          b'factory-root\n',value['metadata'])
        self.assertTrue(result['declared_closure_pinned'])
        self.assertEqual(result['required_distribution_count'],2)
        self.assertEqual(result['unmapped_installed_count'],1)
        self.assertEqual(value['receipt']['distribution_count'],3)
        self.assertEqual(value['receipt']['marker_context'],'trusted-observer')
        self.assertFalse(value['receipt']['application_environment_verified'])

    def test_missing_transitive_distribution_is_known_false_not_silently_omitted(self):
        value=self.inspect(fixture(child=False))
        result=inspect_python_dependencies(b'factory-root==1.0\nfactory-child==2.0\n',
                                          b'factory-root\n',value['metadata'])
        self.assertFalse(result['declared_closure_pinned'])
        self.assertEqual(result['missing_distribution_count'],1)

    def test_private_descriptions_and_hook_contents_not_returned_or_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            previous=set(Path(temporary).iterdir())
            value=self.inspect(fixture())
            self.assertEqual(previous,set(Path(temporary).iterdir()))
        text=json.dumps(value)
        self.assertNotIn('Private package description',text)
        self.assertNotIn('/outside/executed',text)
        self.assertEqual(value['receipt']['startup_hook_files'],1)
        self.assertFalse(value['receipt']['candidate_packages_executed'])
        self.assertFalse(value['receipt']['candidate_archive_extracted'])

    def test_tree_and_metadata_stable_across_repeated_private_reads(self):
        raw=fixture()
        self.assertEqual(self.inspect(raw),self.inspect(raw))
        altered=fixture(hook=False)
        self.assertNotEqual(self.inspect(raw)['receipt']['installed_tree_sha256'],
                            self.inspect(altered)['receipt']['installed_tree_sha256'])

    def test_truncation_appended_archive_links_legacy_and_partial_metadata_refused(self):
        raw=fixture()
        for data in (raw[:1000],raw[:1024],raw+fixture(),fixture(unsafe=True),
                     fixture(legacy=True),fixture(missing_metadata=True),fixture(duplicate_header=True)):
            with self.assertRaises((MetadataUnavailable,tarfile.TarError)):
                self.inspect(data)

    def test_supported_metadata_versions_and_unknown_future_semantics(self):
        for version in ('2.1','2.2','2.3','2.4','2.5','2.6'):
            value=self.inspect(fixture(metadata_version=version))
            self.assertEqual(value['receipt']['metadata_versions'],{version:3})
            self.assertFalse(value['receipt']['import_metadata_verified'])
            self.assertEqual(value['receipt']['import_metadata_fields'],2 if version in ('2.5','2.6') else 0)
        with self.assertRaises(MetadataUnavailable):self.inspect(fixture(metadata_version='99.0'))

    def test_archive_bound_refuses_before_returning_partial_metadata(self):
        with self.assertRaises(MetadataUnavailable):
            inspect_python_image_archive(io.BytesIO(fixture()),max_bytes=1024)


if __name__=='__main__':unittest.main()
