"""One parent-owned repeat-bootstrap operation; never worker-supplied commands."""
import copy
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import shutil
import socket
import tempfile
import threading

from .verdicts import Inconclusive

LIMIT = 4096


def send(stream, value):
    data=json.dumps(value,allow_nan=False).encode()+b'\n'
    if len(data)>LIMIT:raise ValueError('Operations message exceeds bound')
    stream.write(data);stream.flush()


def receive(stream):
    data=stream.readline(LIMIT+1)
    if not data or len(data)>LIMIT or not data.endswith(b'\n'):raise ValueError('Operations message unavailable')
    def pairs(items):
        value={}
        for key,item in items:
            if key in value:raise ValueError('Duplicate operations message key')
            value[key]=item
        return value
    value=json.loads(data,object_pairs_hook=pairs)
    if not isinstance(value,dict):raise ValueError('Invalid operations message')
    return value


def project(value):
    if (not isinstance(value,dict) or value.get('verdict') not in ('pass','fail','inconclusive')
            or type(value.get('abort_suite')) is not bool
            or value['abort_suite']!=(value['verdict']!='pass')
            or value.get('outcome')!=('repeat_bootstrap_incomplete' if value['verdict']=='inconclusive' else 'repeat_bootstrap_checked')):
        raise ValueError('Independent operations result unavailable')
    return dict(verdict=value['verdict'],abort_suite=value['abort_suite'])


def unavailable():return dict(verdict='inconclusive',abort_suite=True)


class OpsBroker:
    """execute() is a trusted bounded closure over owned sandbox/guard/fixtures.

    It invokes repeat_bootstrap and honors its original clocks. The worker gets
    no shell, path, SQL, snapshot, fixture-edit or arbitrary-operation interface.
    The outer deployment must close this capability and dispose its resources.
    """
    def __init__(self, execute, *, request_seconds=5, cleanup_seconds=45, bind_case=None, settle_check=None):
        if (not callable(execute) or any(type(v) not in (int,float) or not math.isfinite(v) or v<=0 for v in (request_seconds,cleanup_seconds))
                or request_seconds>30 or cleanup_seconds>60):raise ValueError('Invalid operations broker configuration')
        if bind_case is not None and not callable(bind_case):raise ValueError("Invalid case binder")
        if settle_check is not None and not callable(settle_check):raise ValueError("Invalid settlement check")
        self.settle_check=settle_check
        self.bind_case=bind_case;self.bound=False
        self.execute=execute;self.request_seconds=request_seconds;self.cleanup_seconds=cleanup_seconds
        self.owner=os.getpid();self.token=secrets.token_hex(32);self._result=None;self.used=False
        self.directory=Path(tempfile.mkdtemp(prefix='factory-ops-broker-'));os.chmod(self.directory,0o700)
        self.path=self.directory/'ops.sock';self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.socket.bind(str(self.path));os.chmod(self.path,0o600);self.socket.listen(1);self.socket.settimeout(.1)
        self.closing=threading.Event();self.idle=threading.Event();self.idle.set();self.connection=None
        self.thread=threading.Thread(target=self._serve,daemon=True);self.thread.start()
    def bind(self, case_id, *, timeout_seconds):
        import re
        if (os.getpid()!=self.owner or self.closing.is_set() or self.used or self.bound
                or not isinstance(case_id,str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,57}',case_id)
                or type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or timeout_seconds<=0):
            raise ValueError('Operations case binding unavailable')
        self.bound=True
        if self.bind_case is not None:self.bind_case(case_id,timeout_seconds=timeout_seconds)

    @property
    def configuration(self):
        if os.getpid()!=self.owner or self.closing.is_set():raise ValueError('Operations capability unavailable')
        return dict(socket=str(self.path),token=self.token)
    @property
    def result(self):
        if self._result is not None and self.settle_check is not None:
            try:self.settle_check()
            except Exception:self._result=unavailable()
        return copy.deepcopy(self._result)
    def _serve(self):
        while not self.closing.is_set():
            try:connection,_=self.socket.accept()
            except socket.timeout:continue
            except OSError:break
            self.connection=connection;self.idle.clear()
            try:
                with connection:
                    connection.settimeout(self.request_seconds)
                    with connection.makefile('rwb') as stream:
                        request=receive(stream)
                        authenticated=isinstance(request.get('token'),str) and hmac.compare_digest(request['token'],self.token)
                        if not authenticated:
                            send(stream,dict(status='refused'));continue
                        if (set(request)!={'token','operation'} or request.get('operation')!='repeat-bootstrap'
                                or self.used or self.closing.is_set() or os.getpid()!=self.owner
                                or self.bind_case is not None and not self.bound):
                            self.used=True;self._result=unavailable();send(stream,dict(status='inconclusive'));continue
                        self.used=True
                        try:
                            observed=project(self.execute())
                            self._result=unavailable() if self.closing.is_set() else observed
                        except Exception:self._result=unavailable()
                        send(stream,dict(status='settled',result=self._result))
            except Exception:pass
            finally:self.connection=None;self.idle.set()
    def wait_idle(self, timeout=None):return self.idle.wait(self.cleanup_seconds if timeout is None else timeout)
    def close(self):
        self.closing.set();self.socket.close()
        connection=self.connection
        if connection is not None:
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        self.thread.join(self.cleanup_seconds)
        if self.thread.is_alive():raise RuntimeError('Operations cleanup incomplete')
        if self.directory.exists():shutil.rmtree(self.directory)
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def request_repeat_bootstrap(configuration, *, timeout=1800):
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=3600:raise ValueError('Invalid operations request timeout')
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(timeout)
    try:
        connection.connect(configuration['socket'])
        with connection.makefile('rwb') as stream:
            send(stream,dict(token=configuration['token'],operation='repeat-bootstrap'))
            response=receive(stream)
            if response.get('status')!='settled':raise Inconclusive('Owned bootstrap operation unavailable')
            value=response['result']
            if (not isinstance(value,dict) or set(value)!={'verdict','abort_suite'}
                    or value['verdict'] not in ('pass','fail','inconclusive')
                    or type(value['abort_suite']) is not bool or value['abort_suite']!=(value['verdict']!='pass')):
                raise ValueError()
            return value
    except (OSError,ValueError,KeyError,TypeError):raise Inconclusive('Owned bootstrap operation unavailable') from None
    finally:connection.close()
