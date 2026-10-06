"""Actual connected client credentials cannot be replaced by same-UID guesses."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from evaluation.cri_client import PrivateCRIClientGuard, serve_private_rpc_once
from evaluation.cri_events import linux_peer_identity
from evaluation.cri_rpc import PrivateCRIRPCConnection


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux actual client credentials')
class CRIClientTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        executable=os.stat('/proc/self/exe')
        self.peer=dict(uid=os.getuid(),gid=os.getgid(),**linux_peer_identity(os.getpid()),
                       exe_device=executable.st_dev,exe_inode=executable.st_ino)
        self.client,self.other=socket.socketpair()
        self.addCleanup(self.client.close);self.addCleanup(self.other.close)
        self.allowed=True
        self.guard=PrivateCRIClientGuard(peer=self.peer,check=lambda reserve:self.allowed,deadline=time.monotonic()+20)

    def test_actual_fd_matches_independent_original_mapping(self):
        self.assertTrue(self.guard(self.client,5))
        self.peer['pid']+=1
        self.assertTrue(self.guard(self.client,5))

    def test_every_peer_attribute_must_match(self):
        for key in self.peer:
            peer=dict(self.peer);peer[key]+=1
            guard=PrivateCRIClientGuard(peer=peer,check=lambda reserve:True,deadline=time.monotonic()+20)
            self.assertFalse(guard(self.client,5),key)

    def test_revocation_deadline_and_closed_socket_refuse(self):
        self.allowed=False;self.assertFalse(self.guard(self.client,5));self.allowed=True
        self.assertFalse(self.guard(self.client,100))
        self.client.close();self.assertFalse(self.guard(self.client,5))

    def test_guard_checks_scope_after_peer_observation(self):
        values=iter((True,False))
        guard=PrivateCRIClientGuard(peer=self.peer,check=lambda reserve:next(values),deadline=time.monotonic()+20)
        self.assertFalse(guard(self.client,5))

    def test_callback_error_returns_refusal_without_private_content(self):
        def broken(reserve):raise RuntimeError('private-client-mapping')
        guard=PrivateCRIClientGuard(peer=self.peer,check=broken,deadline=time.monotonic()+20)
        self.assertFalse(guard(self.client,5))

    def prepare_server(self):
        endpoint=Path(self.temp.name)/'runtime.sock'
        runtime_listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(runtime_listener.close)
        runtime_listener.bind(str(endpoint));runtime_listener.listen(1)
        connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(connection.close);connection.connect(str(endpoint))
        server,_=runtime_listener.accept();self.addCleanup(server.close)
        path=endpoint.stat();invalidations=[]
        runtime=PrivateCRIRPCConnection(connection,peer=dict(self.peer,socket_device=path.st_dev,socket_inode=path.st_ino),
            endpoint=str(endpoint),check=lambda reserve:True,invalidate=lambda:invalidations.append(True),deadline=time.monotonic()+20)
        self.addCleanup(runtime.close)
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(listener.close)
        client_path=Path(self.temp.name)/'client.sock';listener.bind(str(client_path));listener.listen(1)
        consumer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(consumer.close);consumer.connect(str(client_path))
        return listener,runtime,invalidations

    def test_one_client_admission_disposes_listener_and_connections(self):
        listener,runtime,invalidations=self.prepare_server()
        result=serve_private_rpc_once(listener,runtime,client_guard=self.guard,stop=lambda:True,deadline=time.monotonic()+10)
        self.assertEqual(result['outcome'],'observation_window_ended')
        self.assertFalse(result['history_complete']);self.assertEqual(listener.fileno(),-1)
        self.assertTrue(runtime.summary()['descriptors_closed']);self.assertEqual(invalidations,[True])

    def test_wrong_same_uid_client_mapping_invalidates_runtime(self):
        listener,runtime,invalidations=self.prepare_server()
        peer=dict(self.peer,pid=self.peer['pid']+1)
        guard=PrivateCRIClientGuard(peer=peer,check=lambda reserve:True,deadline=time.monotonic()+20)
        with self.assertRaisesRegex(ValueError,'Private RPC client admission unavailable'):
            serve_private_rpc_once(listener,runtime,client_guard=guard,stop=lambda:True,deadline=time.monotonic()+10)
        self.assertEqual(listener.fileno(),-1);self.assertTrue(runtime.summary()['descriptors_closed']);self.assertEqual(invalidations,[True])


    def test_actual_substitute_process_with_same_uid_is_refused(self):
        listener,runtime,invalidations=self.prepare_server()
        first,_=listener.accept();first.close()
        child=subprocess.Popen([sys.executable,'-c',
            "import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1]); print('connected',flush=True); sys.stdin.read()",
            listener.getsockname()],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'connected')
            self.assertIsNone(child.poll())
            with self.assertRaises(ValueError):
                serve_private_rpc_once(listener,runtime,client_guard=self.guard,stop=lambda:True,deadline=time.monotonic()+10)
            self.assertTrue(runtime.summary()['descriptors_closed']);self.assertEqual(invalidations,[True])
        finally:
            child.terminate();child.communicate(timeout=3)
