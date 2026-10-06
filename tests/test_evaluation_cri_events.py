"""Real Unix packet/FD receiver must reject private identity and framing losses."""
import array
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.cri_events import ACK, HEADER, PrivateCRIEventReceiver, linux_peer_identity
from evaluation.cri_staging import PrivateCRIStaging
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_cri_follower import BINDING, SOURCE, frame


UID='12345678-1234-1234-1234-123456789abc'
ENTRY=dict(namespace=BINDING['name'],pod_name=SOURCE['pod_name'],pod_uid=UID,
           container_name=SOURCE['container_name'],restart_index=0)
BOUND=dict(SOURCE,pod_uid=UID)
PATH=f"/var/log/pods/{BINDING['name']}_{SOURCE['pod_name']}_{UID}/{SOURCE['container_name']}/0.log"


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux Unix descriptor receiver')
class CRIEventsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'0.log';self.path.write_bytes(frame(b'private-event-secret'))
        self.fd=os.open(self.path,os.O_RDONLY);self.addCleanup(os.close,self.fd)
        self.sender,self.connection=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.addCleanup(self.sender.close);self.addCleanup(self.connection.close)
        self.sender.settimeout(1)
        self.retention=PrivateCRIRetention(BINDING);self.addCleanup(self.retention.close)
        self.allowed=True;self.event_allowed=True;self.proofs=[]
        self.staging=PrivateCRIStaging(self.retention,check=lambda reserve:self.allowed,deadline=time.monotonic()+90)
        self.addCleanup(self.staging.close)
        self.peer=dict(uid=os.getuid(),gid=os.getgid(),**linux_peer_identity(os.getpid()))
        self.receiver=PrivateCRIEventReceiver(self.staging,self.connection,peer=self.peer,node_uid='node-uid',
            check=lambda reserve:self.allowed,event_check=self.event_check,deadline=time.monotonic()+60)
        self.addCleanup(self.receiver.close)

    def event_check(self,proof,reserve):
        self.proofs.append(proof)
        return self.event_allowed

    def send(self,sequence=1,path=PATH,descriptors=None,device=None,inode=None,magic=b'CRF1',tail=b''):
        observed=os.fstat(self.fd);raw=path.encode('ascii')
        packet=HEADER.pack(magic,sequence,observed.st_dev if device is None else device,
                           observed.st_ino if inode is None else inode,len(raw))+raw+tail
        descriptors=[self.fd] if descriptors is None else descriptors
        rights=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',descriptors))] if descriptors else []
        self.sender.sendmsg([packet],rights)

    def admit(self,sequence=1):
        result=self.receiver.poll()
        self.assertEqual(self.sender.recv(64),ACK.pack(b'CRA1',sequence))
        return result

    def test_unlinked_received_fd_private_until_binding_and_duplicate_open(self):
        self.path.unlink();self.send();result=self.admit()
        self.assertEqual(result['sources'],1);self.assertFalse(result['history_complete'])
        self.assertFalse(self.retention.inspect(['private-event-secret'])['canary_present'])
        self.assertEqual(self.proofs[0]['entry'],ENTRY)
        self.assertNotIn('private-event-secret',repr(result))
        self.staging.bind(ENTRY,BOUND,check=lambda *args:True)
        self.assertTrue(self.retention.inspect(['private-event-secret'])['canary_present'])
        self.send(2);result=self.admit(2)
        self.assertEqual((result['events'],result['sources'],result['duplicate_opens']),(2,1,1))
        self.assertTrue(self.receiver.close()['descriptors_closed'])
        os.fstat(self.fd);self.assertEqual(self.connection.fileno(),-1)
        self.assertTrue(self.retention.inspect(['private-event-secret'])['canary_present'])

    def test_idle_poll_is_nonblocking_and_does_not_attest_absence(self):
        result=self.receiver.poll()
        self.assertEqual(result['events'],0);self.assertTrue(result['valid'])
        self.assertFalse(result['history_complete'])
        self.assertIsNone(self.connection.gettimeout())

    def test_timed_socket_handoff_keeps_idle_poll_nonblocking(self):
        sender,connection=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        connection.settimeout(1)
        receiver=None
        try:
            receiver=PrivateCRIEventReceiver(self.staging,connection,peer=self.peer,
                node_uid='node-uid',check=lambda _:True,event_check=lambda *args:True,
                deadline=time.monotonic()+30)
            self.assertIsNone(connection.gettimeout())
            receipt=receiver.poll()
            self.assertEqual(receipt['events'],0);self.assertTrue(receipt['valid'])
            self.assertFalse(receipt['history_complete'])
        finally:
            if receiver is not None:receiver.close()
            connection.close();sender.close()

    def test_bad_packets_close_all_received_fds_and_staging(self):
        cases=[dict(sequence=2),dict(magic=b'bad!'),dict(device=0),dict(inode=0),
               dict(path=PATH.replace('/var/log/pods/','/tmp/')),
               dict(path=PATH.replace(BINDING['name'],'foreign')),
               dict(path=PATH.replace(UID,UID.upper())),dict(path=PATH.replace('/0.log','/00.log')),
               dict(path=PATH+'.1'),dict(path=PATH+' (deleted)'),dict(tail=b'extra'),
               dict(descriptors=[]),dict(descriptors=[self.fd,self.fd])]
        # UID includes only digits in its first groups; include alpha in the
        # mutation so uppercase/noncanonical UUID is actually a negative.
        cases[6]=dict(path=PATH.replace(UID,'ABCDEFAB-1234-1234-1234-123456789abc'))
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                retention=PrivateCRIRetention(BINDING)
                staging=PrivateCRIStaging(retention,check=lambda *args:True,deadline=time.monotonic()+90)
                receiver=PrivateCRIEventReceiver(staging,self.connection.dup(),peer=self.peer,node_uid='node-uid',check=lambda *args:True,event_check=lambda *args:True,deadline=time.monotonic()+60)
                try:
                    self.send(**kwargs)
                    before=len(os.listdir('/proc/self/fd'))
                    with self.assertRaisesRegex(ValueError,'^Private CRI event admission unavailable$'):receiver.poll()
                    # Receiver's own socket closes. No received FD may remain.
                    self.assertEqual(len(os.listdir('/proc/self/fd')),before-1)
                    self.assertTrue(receiver.summary()['descriptors_closed'])
                    self.assertFalse(retention.inspect(['private-event-secret'])['canary_present'])
                finally:receiver.close();retention.close()

    def test_truncated_data_and_ancillary_close_delivered_fds(self):
        self.sender.sendmsg([b'X'*2048],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.fd]*80))])
        before=len(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertEqual(len(os.listdir('/proc/self/fd')),before-1)

    def test_event_guard_change_retains_only_prior_bound_positive(self):
        self.send();self.admit();self.staging.bind(ENTRY,BOUND,check=lambda *args:True)
        self.event_allowed=False;self.send(2)
        with self.assertRaises(ValueError):self.receiver.poll()
        result=self.retention.inspect(['private-event-secret'])
        self.assertTrue(result['canary_present']);self.assertFalse(result['retention_valid'])
        self.assertTrue(self.receiver.summary()['descriptors_closed'])

    def test_generation_replacement_and_inode_reuse_are_refused(self):
        self.send();self.admit()
        self.send(2,path=PATH.replace('/0.log','/1.log'))
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertTrue(self.receiver.summary()['descriptors_closed'])

    def test_new_inode_at_same_generation_is_refused(self):
        self.send();self.admit()
        replacement=Path(self.temp.name)/'new.log'
        replacement.write_bytes(frame(b'replacement-secret'))
        descriptor=os.open(replacement,os.O_RDONLY)
        try:
            observed=os.fstat(descriptor)
            self.send(2,descriptors=[descriptor],device=observed.st_dev,inode=observed.st_ino)
            with self.assertRaises(ValueError):self.receiver.poll()
            self.assertTrue(self.receiver.summary()['descriptors_closed'])
            self.assertFalse(self.retention.inspect(['replacement-secret'])['canary_present'])
        finally:os.close(descriptor)

    def test_writable_regular_fd_cannot_be_admitted(self):
        writer=os.open(self.path,os.O_RDWR)
        try:
            self.send(descriptors=[writer])
            with self.assertRaises(ValueError):self.receiver.poll()
            self.assertTrue(self.receiver.summary()['descriptors_closed'])
            self.assertFalse(self.retention.inspect(['private-event-secret'])['canary_present'])
        finally:os.close(writer)

    def test_guard_after_staging_discards_unbound_data(self):
        calls=[]
        def changes(proof,reserve):
            calls.append(proof)
            return len(calls)==1
        self.receiver._event_check=changes
        self.send()
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertEqual(self.staging.summary()['staged_bytes'],0)
        self.assertFalse(self.retention.inspect(['private-event-secret'])['canary_present'])
        self.assertTrue(self.receiver.summary()['descriptors_closed'])

    def test_peer_disappears_poll_limit_and_sequence_replay_fail_closed(self):
        self.send();self.admit()
        self.send(sequence=1)
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertTrue(self.receiver.summary()['descriptors_closed'])
        for mode in ('process','limit','deadline'):
            with self.subTest(mode=mode):
                retention=PrivateCRIRetention(BINDING)
                staging=PrivateCRIStaging(retention,check=lambda *args:True,deadline=time.monotonic()+90)
                receiver=PrivateCRIEventReceiver(staging,self.connection if self.connection.fileno()>=0 else self.sender.dup(),peer=self.peer,node_uid='node-uid',check=lambda *args:True,event_check=lambda *args:True,deadline=time.monotonic()+60)
                try:
                    if mode=='limit':receiver._polls=4096
                    if mode=='deadline':receiver._deadline=time.monotonic()+4
                    if mode=='process':
                        with patch('evaluation.cri_events.linux_peer_identity',side_effect=ValueError('private-runtime-diagnostic')):
                            with self.assertRaisesRegex(ValueError,'^Private CRI event admission unavailable$'):receiver.poll()
                    else:
                        with self.assertRaises(ValueError):receiver.poll()
                    self.assertTrue(receiver.summary()['descriptors_closed'])
                finally:receiver.close();retention.close()

    def test_peer_start_mount_credentials_and_lifetime_are_checked(self):
        for field in self.peer:
            with self.subTest(field=field):
                peer=dict(self.peer);peer[field]+=1
                retention=PrivateCRIRetention(BINDING)
                staging=PrivateCRIStaging(retention,check=lambda *args:True,deadline=time.monotonic()+90)
                try:
                    with self.assertRaisesRegex(ValueError,'^Private event receiver unavailable$'):
                        PrivateCRIEventReceiver(staging,self.connection.dup(),peer=peer,node_uid='node-uid',check=lambda *args:True,event_check=lambda *args:True,deadline=time.monotonic()+60)
                    self.assertTrue(staging.summary()['descriptors_closed'])
                finally:staging.close();retention.close()
        self.allowed=False
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertTrue(self.receiver.summary()['descriptors_closed'])

    def test_eof_peer_loss_and_owner_reuse_never_resume(self):
        with patch('evaluation.cri_events.os.getpid',return_value=os.getpid()+1):
            with self.assertRaises(ValueError):self.receiver.poll()
        self.assertTrue(self.receiver.summary()['valid'])
        self.sender.close()
        with self.assertRaises(ValueError):self.receiver.poll()
        self.assertTrue(self.receiver.summary()['descriptors_closed'])
