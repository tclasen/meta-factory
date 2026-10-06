"""Bounded private byte relay on an admitted held CRI runtime connection."""
import math
import socket
import time

from .cri_rpc import MAX_CHUNK_BYTES, PrivateCRIRPCConnection


def relay_private_rpc(client, runtime, *, check_client, stop, deadline):
    """Transfer ownership of both sockets; invalidate collections on every exit.

    check_client(socket, reserve) independently authenticates the operator client
    FD and owner lifetime. stop() is an operator-owned observation-window signal,
    never a runtime EOF or application response. Callbacks must be bounded; run
    this relay in a guarded operator process. No raw bytes enter diagnostics.
    This supplies transport, not gRPC decoding or subscription completeness.
    """
    to_runtime = b''
    to_client = b''
    sent = received = 0
    outcome = 'incomplete'
    try:
        if (not isinstance(client, socket.socket) or client.family != socket.AF_UNIX
                or client.type != socket.SOCK_STREAM
                or not isinstance(runtime, PrivateCRIRPCConnection)
                or not callable(check_client) or not callable(stop)
                or type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise ValueError()
        client.settimeout(None)
        def verify():
            if time.monotonic()+5 >= deadline or check_client(client, 5) is not True:
                raise ValueError()
            runtime.poll()
        while True:
            verify()
            stopping = stop()
            if type(stopping) is not bool:
                raise ValueError()
            if stopping:
                # Unsent bytes mean the window ended with unsettled transport.
                if to_runtime or to_client:
                    raise ValueError()
                outcome = 'observation_window_ended'
                break
            if not to_runtime:
                try:
                    chunk = client.recv(MAX_CHUNK_BYTES, socket.MSG_DONTWAIT)
                except (BlockingIOError, InterruptedError):
                    chunk = None
                verify()
                if chunk == b'':
                    raise ValueError()
                if chunk is not None:
                    to_runtime = chunk
            if to_runtime:
                consumed = runtime.send(to_runtime)
                to_runtime = to_runtime[consumed:]
                sent += consumed
            if not to_client:
                chunk = runtime.receive()
                if chunk is not None:
                    to_client = chunk
            if to_client:
                verify()
                try:
                    consumed = client.send(to_client, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                    if consumed <= 0:
                        raise ValueError()
                except (BlockingIOError, InterruptedError):
                    consumed = 0
                if consumed < 0:
                    raise ValueError()
                to_client = to_client[consumed:]
                received += consumed
                verify()
            time.sleep(.005)
    except Exception:
        raise ValueError('Private runtime relay unavailable') from None
    finally:
        try:
            client.close()
        finally:
            runtime.close()
    return dict(outcome=outcome, sent_bytes=sent, received_bytes=received,
                client_closed=client.fileno() < 0, runtime=runtime.summary(),
                history_complete=False)
