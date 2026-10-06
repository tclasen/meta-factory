"""Real Unix sockets exercise relay bytes, peer guards and disposal."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from evaluation.cri_events import linux_peer_identity
from evaluation.cri_relay import relay_private_rpc
from evaluation.cri_rpc import PrivateCRIRPCConnection


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux held runtime authentication')
class CRIRelayTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        endpoint=Path(self.temp.name)/'runtime.sock'
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(listener.close)
        listener.bind(str(endpoint));listener.listen(1)
        connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(connection.close)
        connection.connect(str(endpoint));self.server,_=listener.accept();self.addCleanup(self.server.close)
        executable=os.stat('/proc/self/exe');path=endpoint.stat()
        peer=dict(uid=os.getuid(),gid=os.getgid(),**linux_peer_identity(os.getpid()),
                  exe_device=executable.st_dev,exe_inode=executable.st_ino,
                  socket_device=path.st_dev,socket_inode=path.st_ino)
        self.invalidations=[];self.allowed=True
        self.runtime=PrivateCRIRPCConnection(connection,peer=peer,endpoint=str(endpoint),
            check=lambda reserve:self.allowed,invalidate=lambda:self.invalidations.append(True),deadline=time.monotonic()+20)
        self.addCleanup(self.runtime.close)
        self.client,self.consumer=socket.socketpair();self.addCleanup(self.client.close);self.addCleanup(self.consumer.close)

    def relay(self, **changes):
        options=dict(check_client=lambda client,reserve:True,stop=lambda:False,deadline=time.monotonic()+10)
        options.update(changes)
        return relay_private_rpc(self.client,self.runtime,**options)

    def assert_disposed(self):
        self.assertEqual(self.client.fileno(),-1)
        self.assertTrue(self.runtime.summary()['descriptors_closed'])
        self.assertEqual(self.invalidations,[True])

    def test_full_duplex_private_bytes_and_intentional_window_end(self):
        complete=threading.Event();errors=[]
        payload=b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'+b'\x00'*200000
        def exchange():
            try:
                self.server.settimeout(3);self.consumer.settimeout(3)
                # Chunked producer/consumer prevents either direction filling.
                for start in range(0,len(payload),10000):
                    chunk=payload[start:start+10000];self.consumer.sendall(chunk)
                    got=b''
                    while len(got)<len(chunk):got+=self.server.recv(len(chunk)-len(got))
                    self.assertEqual(got,chunk);self.server.sendall(got)
                    echoed=b''
                    while len(echoed)<len(chunk):echoed+=self.consumer.recv(len(chunk)-len(echoed))
                    self.assertEqual(echoed,chunk)
                complete.set()
            except BaseException as error:errors.append(error);complete.set()
        thread=threading.Thread(target=exchange);thread.start()
        send=self.runtime.send;calls=[]
        def partial(value):
            calls.append(len(value))
            return 0 if len(calls)==1 else send(value[:1024])
        try:
            with patch.object(self.runtime,'send',side_effect=partial):
                result=self.relay(stop=complete.is_set)
        finally:thread.join(4)
        self.assertGreater(len(calls),100)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        self.assertEqual(result['sent_bytes'],len(payload));self.assertEqual(result['received_bytes'],len(payload))
        self.assertFalse(result['history_complete']);self.assert_disposed()

    def test_client_guard_refusal_prevents_forwarding(self):
        self.consumer.sendall(b'private-request')
        with self.assertRaisesRegex(ValueError,'Private runtime relay unavailable'):
            self.relay(check_client=lambda client,reserve:False)
        self.server.settimeout(1);self.assertEqual(self.server.recv(100),b'');self.assert_disposed()

    def test_runtime_guard_loss_revokes_even_idle_relay(self):
        self.allowed=False
        with self.assertRaises(ValueError):self.relay()
        self.assert_disposed()

    def test_client_eof_is_not_successful_window_completion(self):
        self.consumer.close()
        with self.assertRaises(ValueError):self.relay()
        self.assert_disposed()

    def test_runtime_eof_is_not_successful_window_completion(self):
        self.server.close()
        with self.assertRaises(ValueError):self.relay()
        self.assert_disposed()

    def test_deadline_refusal_disposes_both_connections(self):
        with self.assertRaises(ValueError):self.relay(deadline=time.monotonic()+1)
        self.assert_disposed()

    def test_invalid_window_signal_cannot_complete(self):
        with self.assertRaises(ValueError):self.relay(stop=lambda:'done')
        self.assert_disposed()

    def test_callback_failure_is_sanitized_and_disposed(self):
        def broken(*args):raise RuntimeError('private-content')
        with self.assertRaisesRegex(ValueError,'Private runtime relay unavailable') as error:self.relay(check_client=broken)
        self.assertNotIn('private-content',str(error.exception));self.assert_disposed()
