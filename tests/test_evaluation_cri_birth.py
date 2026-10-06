"""Real recursive node discovery must not infer completeness from empty scans."""
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from evaluation.cri_birth import LinuxCRIBirthWatch
from evaluation.cri_follower import OVERFLOW, LinuxCRIFollower
from evaluation.cri_staging import PrivateCRIStaging
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_cri_follower import BINDING, frame


UID=str(uuid.UUID('11223344-5566-7788-9900-aabbccddeeff'))
ENTRY=dict(namespace=BINDING['name'],pod_name='api',pod_uid=UID,container_name='runtime',restart_index=0)
SOURCE={key:ENTRY[key] for key in ENTRY if key!='restart_index'} | dict(container_id='containerd://late-CID',previous=False)
CANARY=b'private-birth\x00\xff-canary'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Actual Linux recursive inotify')
class CRIBirthTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.allowed=True
        self.r=PrivateCRIRetention(BINDING);self.addCleanup(self.r.close)
        self.m=PrivateCRIStaging(self.r,check=lambda reserve:self.allowed,deadline=time.monotonic()+90)
        self.addCleanup(self.m.close);self.w=None

    def watch(self):
        self.w=LinuxCRIBirthWatch(self.m,self.root,node_uid='node-uid',check=lambda reserve:self.allowed,deadline=self.m._deadline)
        self.addCleanup(self.w.close);return self.w

    def file(self, index=0, namespace=None, pod='api', uid=UID, container='runtime',payload=CANARY):
        directory=self.root/((namespace or BINDING['name'])+'_'+pod+'_'+uid)/container
        directory.mkdir(parents=True,exist_ok=True)
        path=directory/(str(index)+'.log');path.write_bytes(frame(payload));return path

    def test_arms_root_before_tree_birth_and_captures_without_any_cid(self):
        w=self.watch();self.assertEqual(w.summary()['files_seen'],0)
        path=self.file();result=w.poll()
        self.assertEqual((result['files_seen'],result['startup_files'],result['directories_seen']),(1,0,3))
        self.assertEqual(self.m.pending()[0]['entry'],ENTRY)
        self.assertFalse(self.r.inspect(binary_values=[CANARY])['canary_present'])
        self.assertFalse(result['birth_coverage_verified']);self.assertFalse(result['history_complete'])
        self.m.bind(ENTRY,SOURCE,check=lambda proof,reserve:proof['entry']==ENTRY and proof['source']==SOURCE)
        self.assertTrue(self.r.inspect(binary_values=[CANARY])['canary_present'])
        self.assertNotIn(UID,repr(result));self.assertNotIn(CANARY.hex(),repr(result))
        self.assertTrue(w.close()['descriptors_closed'])

    def test_existing_files_are_startup_observations_other_namespaces_not_traversed(self):
        self.file();self.file(namespace='foreign',pod='foreign')
        # A foreign namespace's unsupported/symlink tree must not be opened.
        foreign=self.root/('foreign_other_'+str(uuid.uuid4()));foreign.symlink_to('/does/not/exist')
        w=self.watch();result=w.poll()
        self.assertEqual((result['files_seen'],result['startup_files']),(1,1))
        self.assertEqual(len(self.m.pending()),1)
        self.assertFalse(result['birth_coverage_verified'])

    def test_new_container_and_restart_files_are_discovered_with_exact_indices(self):
        self.file();w=self.watch()
        self.file(index=1,payload=b'restart-canary')
        self.file(container='sidecar',payload=b'sidecar-canary')
        result=w.poll();self.assertEqual(result['files_seen'],3)
        observed={(v['entry']['container_name'],v['entry']['restart_index']) for v in self.m.pending()}
        self.assertEqual(observed,{('runtime',0),('runtime',1),('sidecar',0)})

    def test_borrowed_directory_descriptors_cannot_redirect_and_original_fd_stays_owned(self):
        path=self.file();fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        r=PrivateCRIRetention(BINDING)
        follower=LinuxCRIFollower(r,SOURCE,fd,'0.log',node_uid='node-uid',check=lambda *args:True,deadline=time.monotonic()+90)
        try:
            os.close(fd);fd=None
            follower.poll();self.assertTrue(r.inspect(binary_values=[CANARY])['canary_present'])
        finally:
            follower.close();r.close()
            if fd is not None:os.close(fd)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);r=PrivateCRIRetention(BINDING)
        follower=LinuxCRIFollower(r,SOURCE,fd,'0.log',node_uid='node-uid',check=lambda *args:True,deadline=time.monotonic()+90)
        try:
            follower.close();self.assertTrue(os.fstat(fd))
        finally:os.close(fd);r.close()

    def test_observed_directory_loss_or_missed_file_create_is_a_sticky_gap(self):
        for mode in ('removed-directory','removed-file','moved-directory'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                r=PrivateCRIRetention(BINDING);m=PrivateCRIStaging(r,check=lambda reserve:True,deadline=time.monotonic()+90)
                root=Path(directory)
                # Arm every directory before a file that might vanish is created.
                container=root/(ENTRY['namespace']+'_api_'+UID)/'runtime';container.mkdir(parents=True)
                w=LinuxCRIBirthWatch(m,root,node_uid='node-uid',check=lambda reserve:True,deadline=m._deadline)
                try:
                    if mode=='removed-directory':shutil.rmtree(container.parent)
                    elif mode=='moved-directory':container.rename(container.with_name('renamed'))
                    else:
                        path=container/'0.log';path.write_bytes(frame(CANARY));path.unlink()
                    fds=[state['fd'] for state in w._directories.values()]+[w._notify_fd]
                    with self.assertRaises(ValueError):w.poll()
                    self.assertTrue(w.summary()['discovery_gap'])
                    self.assertTrue(w.close()['descriptors_closed'])
                    for fd in fds:
                        with self.assertRaises(OSError):os.fstat(fd)
                    with self.assertRaises(ValueError):w.poll()
                finally:w.close();r.close()

    def test_prearm_descendant_create_delete_can_be_unobservable_and_never_proves_coverage(self):
        w=self.watch();path=self.file();path.unlink()
        result=w.poll()
        # Parent birth is observable, but the child's log predates its watch.
        self.assertEqual(result['files_seen'],0)
        self.assertFalse(result['birth_coverage_verified']);self.assertFalse(result['history_complete'])
        self.assertEqual(self.m.pending(),[])

    def test_wrong_names_symlinks_old_rotations_and_nonregular_files_refuse(self):
        for mode in ('uid','pod','container','symlink','file-symlink','fifo','rotated','noncanonical'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);uid='not-uuid' if mode=='uid' else UID
                pod='BAD' if mode=='pod' else 'api';container_name='BAD' if mode=='container' else 'runtime'
                container=root/(ENTRY['namespace']+'_'+pod+'_'+uid)/container_name
                container.mkdir(parents=True)
                if mode=='symlink':container.rmdir();container.symlink_to(root)
                elif mode=='file-symlink':(container/'0.log').symlink_to(root/'elsewhere')
                elif mode=='fifo':os.mkfifo(container/'0.log')
                elif mode=='rotated':(container/'0.log.older').write_bytes(frame(CANARY));(container/'0.log').write_bytes(b'')
                else:(container/('00.log' if mode=='noncanonical' else '0.log')).write_bytes(frame(CANARY))
                r=PrivateCRIRetention(BINDING);m=PrivateCRIStaging(r,check=lambda reserve:True,deadline=time.monotonic()+90)
                try:
                    with self.assertRaisesRegex(ValueError,'^Private CRI discovery unavailable$'):
                        LinuxCRIBirthWatch(m,root,node_uid='node-uid',check=lambda reserve:True,deadline=m._deadline)
                    self.assertTrue(m.close()['descriptors_closed'])
                    self.assertFalse(r.inspect(binary_values=[CANARY])['canary_present'])
                finally:m.close();r.close()

    def test_overflow_bounds_owner_and_guards_close_every_descriptor(self):
        for mode in ('overflow','directories','entries','deadline','guard','polls'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                r=PrivateCRIRetention(BINDING);allowed=[True]
                m=PrivateCRIStaging(r,check=lambda reserve:True,deadline=time.monotonic()+90)
                w=LinuxCRIBirthWatch(m,directory,node_uid='node-uid',check=lambda reserve:allowed[0],deadline=m._deadline)
                try:
                    if mode=='deadline':w._deadline=time.monotonic()
                    if mode=='guard':allowed[0]=False
                    if mode=='polls':w._polls=4096
                    if mode in ('directories','entries'):
                        (Path(directory)/(ENTRY['namespace']+'_api_'+UID)).mkdir()
                    context=patch('evaluation.cri_birth.os.read',return_value=struct.pack('iIII',-1,OVERFLOW,0,0)) if mode=='overflow' else patch('evaluation.cri_birth.MAX_DIRECTORIES',1) if mode=='directories' else patch('evaluation.cri_birth.MAX_ENTRIES',0) if mode=='entries' else patch('evaluation.cri_birth.MAX_ENTRIES',512)
                    # entries limit applies while recursively scanning a populated child.
                    if mode=='entries':
                        (Path(directory)/(ENTRY['namespace']+'_api_'+UID)/'runtime').mkdir()
                    with context,self.assertRaises(ValueError):w.poll()
                    self.assertTrue(w.close()['descriptors_closed']);self.assertTrue(w.summary()['discovery_gap'])
                finally:w.close();r.close()
        self.file();w=self.watch()
        with patch('evaluation.cri_birth.os.getpid',return_value=-1):
            for operation in (w.poll,w.summary,w.close):
                with self.assertRaises(ValueError):operation()
        w.poll();self.assertTrue(w.summary()['valid'])
