"""Specification preparation cannot publish unreviewed bytes or overwrite data."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from evaluation.evidence import Attempt,atomic_json
from evaluation.preparation import prepare_specification,read_regular,write_file


class PreparationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.workload=self.root/'workload'
        (self.workload/'builder/public').mkdir(parents=True);(self.workload/'review').mkdir()
        (self.workload/'builder/APPLICATION.md').write_text('Reviewed workload')
        (self.workload/'builder/public/check.py').write_text('raise RuntimeError("never execute")\n')
        self.approval=self.workload/'review/WORKLOAD-APPROVAL.json'
        self.expected={str(path.relative_to(self.workload)):hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.workload/'builder').rglob('*') if path.is_file()}
        atomic_json(self.approval,dict(schema_version=1,approval_type='workload_and_envelope_review_not_suite_freeze',workload_sha256=self.expected))
        (self.workload/'review/holdout.txt').write_text('private protected data')
        self.destination=self.root/'spec';self.clock=[10]
        self.attempt=Attempt(self.root/'evidence',{});self.addCleanup(self.attempt.close)

    def prepare(self,**kwargs):
        return prepare_specification(self.attempt,self.workload,kwargs.pop('destination',self.destination),
            monotonic_deadline=100,wall_deadline=100,monotonic=lambda:self.clock[0],wall=lambda:self.clock[0],**kwargs)

    def receipt(self):return json.loads((self.attempt.directory/'specification-preparation.json').read_text())

    def test_exact_reviewed_copy_excludes_operator_records_and_does_not_execute(self):
        with patch('subprocess.Popen',side_effect=AssertionError('No process allowed')):
            value=self.prepare()
        self.assertEqual(value['outcome'],'specification_prepared')
        self.assertEqual(set(value['files']),{'APPLICATION.md','public/check.py'})
        for name,digest in value['files'].items():
            path=self.destination/name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),digest)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o444)
        for directory in (self.destination,self.destination/'public'):
            mode=stat.S_IMODE(directory.stat().st_mode)
            self.assertEqual(mode & 0o222,0)
            self.assertEqual(mode & 0o055,0o055)
        self.assertFalse((self.destination/'review').exists())
        self.assertEqual(value,self.receipt())

    def test_unreviewed_changed_and_missing_files_do_not_create_destination(self):
        for mode in ('unreviewed','changed','missing'):
            with self.subTest(mode=mode):
                # Independent ownership/evidence for each failed attempt.
                with Attempt(self.root/('evidence-'+mode),{}) as attempt:
                    path=self.workload/'builder/APPLICATION.md';original=path.read_bytes()
                    if mode=='unreviewed':(self.workload/'builder/extra').write_text('unapproved')
                    elif mode=='changed':path.write_bytes(original+b'changed')
                    else:path.unlink()
                    try:
                        with self.assertRaises(ValueError):prepare_specification(attempt,self.workload,self.root/('spec-'+mode),monotonic_deadline=100,wall_deadline=100,monotonic=lambda:10,wall=lambda:10)
                        self.assertFalse((self.root/('spec-'+mode)).exists())
                    finally:
                        path.write_bytes(original);(self.workload/'builder/extra').unlink(missing_ok=True)

    def test_existing_destination_is_not_overwritten_or_claimed(self):
        self.destination.mkdir();(self.destination/'owned').write_text('retain')
        with self.assertRaises(FileExistsError):self.prepare()
        self.assertEqual((self.destination/'owned').read_text(),'retain')
        self.assertFalse(self.receipt()['destination_created'])
        self.assertNotIn('retained_destination',self.receipt())

    def test_symlink_hardlink_and_fifo_sources_are_refused_without_opening(self):
        for mode in ('symlink','hardlink','fifo'):
            with self.subTest(mode=mode):
                path=self.workload/'builder/unsafe'
                if mode=='symlink':path.symlink_to(self.workload/'builder/APPLICATION.md')
                elif mode=='hardlink':os.link(self.workload/'builder/APPLICATION.md',path)
                else:os.mkfifo(path)
                try:
                    with Attempt(self.root/('evidence-'+mode),{}) as attempt:
                        with self.assertRaises(ValueError):prepare_specification(attempt,self.workload,self.root/('spec-'+mode),monotonic_deadline=100,wall_deadline=100,monotonic=lambda:10,wall=lambda:10)
                finally:path.unlink()

    def test_mount_overlap_and_destination_link_are_refused(self):
        for destination in (self.workload/'spec',self.attempt.directory/'spec',Path(__file__).resolve().parents[1]/'spec'):
            with self.assertRaises(ValueError):self.prepare(destination=destination)
        link=self.root/'link';link.symlink_to(self.destination)
        with self.assertRaises(ValueError):self.prepare(destination=link)
        self.assertFalse(self.destination.exists())

    def test_byte_and_file_limits_prevent_copy(self):
        for key in ('max_bytes','max_files'):
            with Attempt(self.root/('evidence-'+key),{}) as attempt:
                with self.assertRaises(ValueError):prepare_specification(attempt,self.workload,self.root/('spec-'+key),monotonic_deadline=100,wall_deadline=100,monotonic=lambda:10,wall=lambda:10,**{key:1})
                self.assertFalse((self.root/('spec-'+key)).exists())

    def test_deadline_expiry_retains_owned_incomplete_copy(self):
        def expire(path,data):write_file(path,data);self.clock[0]=101
        with patch('evaluation.preparation.write_file',side_effect=expire):
            with self.assertRaises(TimeoutError):self.prepare()
        self.assertTrue(self.receipt()['destination_created'])
        self.assertEqual(self.receipt()['outcome'],'specification_preparation_incomplete')
        self.assertEqual(self.receipt()['retained_destination'],str(self.destination))

    def test_source_and_review_changes_during_copy_revoke_receipt(self):
        for mode in ('source','review'):
            with self.subTest(mode=mode):
                with Attempt(self.root/('evidence-'+mode),{}) as attempt:
                    source=self.workload/'builder/APPLICATION.md';old_source=source.read_bytes();old_review=self.approval.read_bytes()
                    def change(path,data):
                        write_file(path,data)
                        if mode=='source':source.write_bytes(old_source+b'changed')
                        else:self.approval.write_bytes(old_review+b'\n')
                    try:
                        with patch('evaluation.preparation.write_file',side_effect=change):
                            with self.assertRaises(ValueError):prepare_specification(attempt,self.workload,self.root/('spec-'+mode),monotonic_deadline=100,wall_deadline=100,monotonic=lambda:10,wall=lambda:10)
                        receipt=json.loads((attempt.directory/'specification-preparation.json').read_text())
                        self.assertEqual(receipt['outcome'],'specification_preparation_incomplete')
                        self.assertTrue(receipt['destination_created'])
                    finally:source.write_bytes(old_source);self.approval.write_bytes(old_review)

    def test_partial_write_failure_is_retained_and_not_retried(self):
        with patch('evaluation.preparation.write_file',side_effect=OSError('private disk detail')):
            with self.assertRaises(OSError):self.prepare()
        self.assertEqual(self.receipt()['error_type'],'OSError')
        self.assertNotIn('private disk detail',json.dumps(self.receipt()))
        with self.assertRaises(FileExistsError):self.prepare(destination=self.root/'retry')
        self.assertFalse((self.root/'retry').exists())

    def test_unsafe_approval_paths_and_duplicate_keys_are_refused(self):
        for name in ('../outside','builder/../outside','/builder/absolute','review/holdout.txt'):
            with Attempt(self.root/('path-'+hashlib.sha256(name.encode()).hexdigest()[:8]),{}) as attempt:
                atomic_json(self.approval,dict(schema_version=1,approval_type='workload_and_envelope_review_not_suite_freeze',workload_sha256={name:'0'*64}))
                with self.assertRaises(ValueError):prepare_specification(attempt,self.workload,self.root/('spec-'+hashlib.sha256(name.encode()).hexdigest()[:8]),monotonic_deadline=100,wall_deadline=100,monotonic=lambda:10,wall=lambda:10)
        self.approval.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError):self.prepare()

    def test_workload_inside_controller_checkout_can_be_copied_outside(self):
        import shutil
        repository=Path(__file__).resolve().parents[1]
        planning=repository/'.factory-planning';planning.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='specification-fixture-',dir=planning) as directory:
            workload=Path(directory)/'workload';shutil.copytree(self.workload,workload)
            value=prepare_specification(self.attempt,workload,self.destination,monotonic_deadline=100,wall_deadline=100,monotonic=lambda:10,wall=lambda:10)
        self.assertEqual(value['outcome'],'specification_prepared')
        self.assertEqual(set(value['files']),{'APPLICATION.md','public/check.py'})

    def test_parent_link_inserted_between_inventory_and_read_is_refused(self):
        directory=self.workload/'builder/public'
        saved=self.workload/'builder/saved-public'
        external=self.root/'external';external.mkdir()
        (external/'check.py').write_text('unreviewed external bytes')
        original=read_regular
        def replace_parent(path,limit,check):
            if Path(path)==directory/'check.py' and not directory.is_symlink():
                directory.rename(saved);directory.symlink_to(external,target_is_directory=True)
            return original(path,limit,check)
        try:
            with patch('evaluation.preparation.read_regular',side_effect=replace_parent):
                with self.assertRaises(OSError):self.prepare()
            self.assertFalse(self.destination.exists())
            self.assertEqual(self.receipt()['outcome'],'specification_preparation_incomplete')
        finally:
            directory.unlink();saved.rename(directory)

    def test_held_parent_handle_cannot_be_redirected_before_file_open(self):
        directory=self.root/'read-parent';directory.mkdir()
        (directory/'file').write_bytes(b'original held bytes')
        external=self.root/'external';external.mkdir()
        (external/'file').write_bytes(b'unreviewed replacement')
        saved=self.root/'saved-parent';original_open=os.open
        def replace_after_parent_open(path,flags,*args,**kwargs):
            descriptor=original_open(path,flags,*args,**kwargs)
            if path=='read-parent':
                directory.rename(saved);directory.symlink_to(external,target_is_directory=True)
            return descriptor
        with patch('evaluation.preparation.os.open',side_effect=replace_after_parent_open):
            self.assertEqual(read_regular(directory/'file',1024,lambda:None),b'original held bytes')

    def test_approval_parent_link_replacement_is_refused(self):
        review=self.workload/'review';saved=self.workload/'saved-review'
        external=self.root/'external-review';external.mkdir()
        (external/'WORKLOAD-APPROVAL.json').write_bytes(self.approval.read_bytes())
        original=read_regular
        def replace_parent(path,limit,check):
            if Path(path)==self.approval:
                review.rename(saved);review.symlink_to(external,target_is_directory=True)
            return original(path,limit,check)
        try:
            with patch('evaluation.preparation.read_regular',side_effect=replace_parent):
                with self.assertRaises(OSError):self.prepare()
            self.assertFalse(self.destination.exists())
        finally:
            review.unlink();saved.rename(review)
