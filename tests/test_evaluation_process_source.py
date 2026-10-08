"""Selected process/root identity, credential mismatch and namespace drift."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.process_source_probe import inspect_process_source, ProcessSourceUnavailable


class ProcessSourceTest(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.proc=self.root/'proc';self.process=self.proc/'321'
        (self.process/'ns').mkdir(parents=True)
        self.filesystem=self.root/'filesystem';(self.filesystem/'srv/app').mkdir(parents=True)
        self.code=self.filesystem/'srv/app/worker.py';self.code.write_bytes(b'private source canary');self.code.chmod(0o644)
        self.binary=self.root/'executable';self.binary.write_bytes(b'independent interpreter');self.binary.chmod(0o755)
        (self.process/'root').symlink_to(self.filesystem,target_is_directory=True)
        (self.process/'exe').symlink_to(self.binary)
        for name in ('pid','mnt','net'):(self.process/'ns'/name).write_bytes(b'namespace')
        self.write_stat('123')
        (self.process/'status').write_text('Uid:\t10001\t10001\t10001\t10001\nGid:\t10001\t10001\t10001\t10001\n')
        (self.process/'cmdline').write_bytes(b'python\0-m\0app.worker\0')
        self.selection={'/srv/app/worker.py':dict(sha256=hashlib.sha256(self.code.read_bytes()).hexdigest(),size=self.code.stat().st_size,mode=0o644)}

    def write_stat(self, ticks):
        (self.process/'stat').write_text('321 (worker name) '+' '.join(['S',*['0']*18,ticks]))

    def observe(self, **changes):
        arguments=dict(pid=321,start_ticks='123',executable_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                       selection=self.selection,argv=['python','-m','app.worker'],uid=10001,gid=10001,proc=self.proc)
        arguments.update(changes);return inspect_process_source(**arguments)

    def test_process_root_selected_source_and_credentials_without_private_values(self):
        value=self.observe()
        for key in ('snapshot_stable','selected_source_bytes_match','selected_source_modes_match',
                    'selected_argv_match','selected_uid_match','selected_gid_match','executable_match'):
            self.assertIs(value[key],True)
        self.assertFalse(value['loaded_modules_verified']);self.assertFalse(value['pod_attribution_verified'])
        text=json.dumps(value)
        for private in ('/srv/app/worker.py','private source canary','app.worker','worker name'):
            self.assertNotIn(private,text)

    def test_stable_known_source_mode_credentials_argv_and_executable_mismatches_false(self):
        self.code.write_bytes(b'changed source');self.code.chmod(0o600)
        value=self.observe(uid=999,gid=999,argv=['wrong'],executable_sha256='0'*64)
        for key in ('selected_source_bytes_match','selected_source_modes_match','selected_uid_match',
                    'selected_gid_match','selected_argv_match','executable_match'):
            self.assertIs(value[key],False)

    def test_changed_start_ticks_refuse_even_if_files_and_executable_match(self):
        self.write_stat('124')
        with self.assertRaises(ProcessSourceUnavailable):self.observe()

    def test_source_link_and_parent_link_cannot_escape_held_process_root(self):
        self.code.unlink();self.code.symlink_to(self.binary)
        with self.assertRaises(OSError):self.observe()
        self.code.unlink();(self.filesystem/'srv/app').rmdir()
        (self.filesystem/'srv/app').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):self.observe()

    def test_rebinding_process_root_during_reads_refuses_old_matching_files(self):
        replacement=self.root/'replacement';replacement.mkdir()
        original=os.read;changed=[]
        def mutate(descriptor,count):
            result=original(descriptor,count)
            if result and not changed:
                (self.process/'root').unlink();(self.process/'root').symlink_to(replacement,target_is_directory=True)
                changed.append(True)
            return result
        with patch('evaluation.process_source_probe.os.read',side_effect=mutate):
            with self.assertRaises(ProcessSourceUnavailable):self.observe()

    def test_parent_replaced_after_leaf_read_refuses_old_descriptor_view(self):
        original=os.read;changed=[]
        def mutate(descriptor,count):
            result=original(descriptor,count)
            if result==b'private source canary' and not changed:
                old=self.filesystem/'srv/app';old.rename(self.filesystem/'srv/old')
                old.mkdir();(old/'worker.py').write_bytes(b'different current source')
                changed.append(True)
            return result
        with patch('evaluation.process_source_probe.os.read',side_effect=mutate):
            with self.assertRaises(ProcessSourceUnavailable):self.observe()


if __name__=='__main__':unittest.main()
