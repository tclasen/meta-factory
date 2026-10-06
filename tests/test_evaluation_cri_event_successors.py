"""A native open packet cannot itself approve a replacement generation."""
import array
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest

from evaluation.cri_events import ACK, HEADER, PrivateCRIEventReceiver, linux_peer_identity
from evaluation.cri_staging import PrivateCRIStaging
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_cri_events import ENTRY, BOUND, PATH
from test_evaluation_cri_follower import BINDING, frame


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux Unix descriptor receiver')
class EventSuccessorTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.old=Path(self.temp.name)/'old';self.new=Path(self.temp.name)/'new'
        self.old.write_bytes(frame(b'old-positive'));self.new.write_bytes(frame(b'new-positive'))
        self.old_fd=os.open(self.old,os.O_RDONLY);self.new_fd=os.open(self.new,os.O_RDONLY)
        self.addCleanup(os.close,self.old_fd);self.addCleanup(os.close,self.new_fd)
        self.sender,connection=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.addCleanup(self.sender.close);self.sender.settimeout(.1)
        self.retention=PrivateCRIRetention(BINDING);self.addCleanup(self.retention.close)
        self.staging=PrivateCRIStaging(self.retention,check=lambda _:True,deadline=time.monotonic()+60)
        self.addCleanup(self.staging.close)
        self.approved=True;self.proofs=[]
        peer=dict(uid=os.getuid(),gid=os.getgid(),**linux_peer_identity(os.getpid()))
        self.receiver=PrivateCRIEventReceiver(self.staging,connection,peer=peer,node_uid='node-uid',
            check=lambda _:True,event_check=lambda *args:True,deadline=time.monotonic()+45,
            successor_check=self.boundary)
        self.addCleanup(self.receiver.close)

    def boundary(self,proof,reserve):
        self.proofs.append(proof)
        return self.approved

    def send(self,fd,sequence):
        s=os.fstat(fd);path=PATH.encode()
        self.sender.sendmsg([HEADER.pack(b'CRF1',sequence,s.st_dev,s.st_ino,len(path))+path],
            [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])

    def admit(self,fd,sequence):
        self.send(fd,sequence);r=self.receiver.poll()
        self.assertEqual(self.sender.recv(64),ACK.pack(b'CRA1',sequence));return r

    def test_successor_and_duplicates_use_separate_admission_then_late_binding(self):
        self.admit(self.old_fd,1);self.old.unlink()
        r=self.admit(self.new_fd,2)
        self.assertEqual((r['events'],r['sources'],r['successors']),(2,1,1))
        self.assertEqual(len(self.proofs),2)
        self.assertEqual(self.proofs[0]['event']['entry'],ENTRY)
        self.assertEqual(self.proofs[0]['boundary']['source'],ENTRY)
        self.assertEqual(self.proofs[0]['event']['identity'],self.proofs[0]['boundary']['new_file'])
        self.assertFalse(self.retention.inspect(['new-positive'])['canary_present'])
        self.staging.bind(ENTRY,BOUND,check=lambda proof,reserve:len(proof['files'])==2)
        self.assertTrue(self.retention.inspect(['new-positive'])['canary_present'])
        self.assertEqual(self.admit(self.new_fd,3)['duplicate_opens'],1)
        self.assertFalse(r['history_complete'])

    def test_unapproved_boundary_never_acknowledges_and_preserves_bound_positive(self):
        self.admit(self.old_fd,1);self.staging.bind(ENTRY,BOUND,check=lambda *args:True)
        self.approved=False;self.send(self.new_fd,2)
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertEqual(self.sender.recv(64),b'')
        self.assertTrue(self.retention.inspect(['old-positive'])['canary_present'])
        self.assertFalse(self.retention.inspect(['old-positive'])['retention_valid'])
        self.assertTrue(self.receiver.close()['descriptors_closed'])

    def test_retired_identity_cannot_return_as_successor(self):
        self.admit(self.old_fd,1);self.admit(self.new_fd,2)
        self.staging.bind(ENTRY,BOUND,check=lambda *args:True)
        self.send(self.old_fd,3)
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertTrue(self.retention.inspect(['old-positive'])['canary_present'])
        self.assertTrue(self.receiver.close()['descriptors_closed'])

    def test_late_retired_write_refuses_native_pipeline_preserving_positive(self):
        self.admit(self.old_fd,1);self.admit(self.new_fd,2)
        self.staging.bind(ENTRY,BOUND,check=lambda *args:True)
        with self.old.open('ab') as writer:writer.write(frame(b'late'))
        with self.assertRaises(ValueError):self.staging.poll()
        self.send(self.new_fd,3)
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertTrue(self.retention.inspect(['old-positive'])['canary_present'])
        self.assertFalse(self.retention.inspect(['old-positive'])['retention_valid'])
        self.assertTrue(self.receiver.close()['descriptors_closed'])
