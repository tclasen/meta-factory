"""Held-RPC refusal closes real collection FDs while retaining captured positives.

API/runtime metadata are independent synthetic fixtures; sockets/files are real.
This is lifecycle composition evidence, not native log attribution or acceptance.
"""
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest

from evaluation.cri_client import PrivateCRIClientGuard
from evaluation.cri_events import linux_peer_identity
from evaluation.cri_live_collection import PrivateCRILiveCollection
from evaluation.cri_relay import relay_private_rpc
from evaluation.cri_rpc import PrivateCRIRPCConnection
from test_evaluation_cri_binding import ENTRY, NODE, pending_history
from test_evaluation_cri_follower import frame
from test_evaluation_cri_runtime_event import runtime_event


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux authenticated RPC sockets')
class RPCCollectionTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.path=root/'0.log';self.path.write_bytes(frame(b'rpc-private-positive\n'))
        self.borrowed=os.open(self.path,os.O_RDONLY);self.addCleanup(os.close,self.borrowed)
        self.collection=PrivateCRILiveCollection(pending_history(),node_uid='node-uid',node_name='node-1',
            check=lambda reserve:True,deadline=time.monotonic()+60)
        self.addCleanup(self.collection.release)
        def file_check(proof,reserve):
            observed=os.fstat(self.borrowed)
            return proof['entry']==ENTRY and proof['projection']['file_identity']==dict(node_uid='node-uid',device=observed.st_dev,inode=observed.st_ino)
        self.collection.feed(json.dumps(runtime_event()).encode())
        self.collection.bind(ENTRY,NODE,self.borrowed,check=file_check);self.collection.poll()
        self.owned=next(iter(self.collection._followers.values()))._current['fd']
        self.assertTrue(self.collection.inspect(binary_values=[b'rpc-private-positive'])['canary_present'])
        endpoint=root/'runtime.sock'
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(listener.close)
        listener.bind(str(endpoint));listener.listen(1)
        connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(connection.close)
        connection.connect(str(endpoint));self.server,_=listener.accept();self.addCleanup(self.server.close)
        executable=os.stat('/proc/self/exe');path=endpoint.stat()
        self.peer=dict(uid=os.getuid(),gid=os.getgid(),**linux_peer_identity(os.getpid()),
            exe_device=executable.st_dev,exe_inode=executable.st_ino)
        self.allowed=True;self.invalidations=[]
        def invalidate():
            self.invalidations.append(True)
            self.collection.close()
        self.runtime=PrivateCRIRPCConnection(connection,peer=dict(self.peer,socket_device=path.st_dev,socket_inode=path.st_ino),
            endpoint=str(endpoint),check=lambda reserve:self.allowed,invalidate=invalidate,deadline=time.monotonic()+20)
        self.addCleanup(self.runtime.close)
        self.endpoint=endpoint
        self.client,self.consumer=socket.socketpair();self.addCleanup(self.client.close);self.addCleanup(self.consumer.close)
        self.client_allowed=True
        self.client_guard=PrivateCRIClientGuard(peer=self.peer,check=lambda reserve:self.client_allowed,deadline=time.monotonic()+20)

    def relay(self,**options):
        kwargs=dict(check_client=self.client_guard,stop=lambda:False,deadline=time.monotonic()+10)
        kwargs.update(options)
        return relay_private_rpc(self.client,self.runtime,**kwargs)

    def assert_positive_preserved_and_owned_resources_closed(self):
        self.assertEqual(self.invalidations,[True])
        self.assertEqual(self.client.fileno(),-1)
        self.assertTrue(self.runtime.summary()['descriptors_closed'])
        with self.assertRaises(OSError):os.fstat(self.owned)
        os.fstat(self.borrowed)
        summary=self.collection.summary()
        self.assertFalse(summary['valid']);self.assertTrue(summary['metadata_released'])
        self.assertTrue(summary['descriptors_closed']);self.assertFalse(summary['history_complete'])
        observed=self.collection.inspect(binary_values=[b'rpc-private-positive'])
        self.assertTrue(observed['canary_present']);self.assertFalse(observed['retention_valid'])
        with self.assertRaises(ValueError):self.collection.poll()
        self.assertTrue(self.collection.inspect(binary_values=[b'rpc-private-positive'])['canary_present'])
        self.runtime.close();self.assertEqual(self.invalidations,[True])

    def test_runtime_eof_preserves_positive_and_closes_collection(self):
        self.server.close()
        with self.assertRaises(ValueError):self.relay()
        self.assert_positive_preserved_and_owned_resources_closed()

    def test_client_eof_preserves_positive_and_closes_collection(self):
        self.consumer.close()
        with self.assertRaises(ValueError):self.relay()
        self.assert_positive_preserved_and_owned_resources_closed()

    def test_runtime_guard_loss_preserves_positive_and_closes_collection(self):
        self.allowed=False
        with self.assertRaises(ValueError):self.relay()
        self.assert_positive_preserved_and_owned_resources_closed()

    def test_client_owner_guard_loss_preserves_positive_and_closes_collection(self):
        self.client_allowed=False
        with self.assertRaises(ValueError):self.relay()
        self.assert_positive_preserved_and_owned_resources_closed()

    def test_runtime_endpoint_replacement_preserves_positive_and_closes_collection(self):
        self.endpoint.rename(self.endpoint.with_suffix('.original'))
        replacement=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(replacement.close)
        replacement.bind(str(self.endpoint))
        with self.assertRaises(ValueError):self.relay()
        self.assert_positive_preserved_and_owned_resources_closed()

    def test_deadline_exhaustion_preserves_positive_and_closes_collection(self):
        with self.assertRaises(ValueError):self.relay(deadline=time.monotonic()+1)
        self.assert_positive_preserved_and_owned_resources_closed()

    def test_callback_failure_preserves_positive_and_closes_collection(self):
        def broken(*args):raise RuntimeError('private-diagnostic')
        with self.assertRaisesRegex(ValueError,'Private runtime relay unavailable') as error:self.relay(check_client=broken)
        self.assertNotIn('private-diagnostic',str(error.exception))
        self.assert_positive_preserved_and_owned_resources_closed()

    def test_window_end_invalidates_collection_without_complete_history_claim(self):
        result=self.relay(stop=lambda:True)
        self.assertEqual(result['outcome'],'observation_window_ended');self.assertFalse(result['history_complete'])
        self.assert_positive_preserved_and_owned_resources_closed()
