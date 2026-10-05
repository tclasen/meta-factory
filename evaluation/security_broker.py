"""Sanitized private parent observations for password storage and log canaries.

Requests expose neither SQL, credential rows, hash profiles, source identities,
log text nor command/path selection. Actual inspection and its reviewed scope
remain parent-side; this channel is not a security verifier or scope attestation.
"""
import hmac
import socket

from .audit_broker import AuditBroker,AuditObservationError,receive,send
from .evidence import positive
from .secret_scan import canary_patterns


OPERATIONS = {'password_storage','log_canaries'}
FAILURES = {
    'password_storage': {'plaintext','forbidden_algorithm','wrong_defaults','reused_salt','password_mismatch'},
    'log_canaries': {'canary_present'},
}
RECEIPT_FIELDS = {'verdict','reason','observations_checked'}


class SecurityObservationError(AuditObservationError):
    pass


def request_values(operation,canaries):
    if not isinstance(operation,str) or operation not in OPERATIONS:
        raise ValueError('Unreviewed security operation')
    if operation=='password_storage':
        if canaries is not None:raise ValueError('Password storage accepts no worker-selected scope')
    else:
        canary_patterns(canaries)


def project(operation,value,*,wire=False):
    """Only finite counts and enumerated verdicts/reasons cross the capability."""
    if not isinstance(operation,str) or operation not in OPERATIONS or not isinstance(value,dict) or not RECEIPT_FIELDS<=value.keys():
        raise ValueError('Invalid sanitized security receipt')
    if wire and set(value)!=RECEIPT_FIELDS:
        raise ValueError('Unexpected security receipt fields')
    verdict,reason,count=(value[key] for key in ('verdict','reason','observations_checked'))
    maximum=64 if operation=='password_storage' else 128
    if (not isinstance(verdict,str) or verdict not in ('pass','fail','inconclusive')
            or not isinstance(reason,str) or type(count) is not int or not 0<=count<=maximum):
        raise ValueError('Invalid sanitized security receipt')
    if verdict=='pass':
        minimum=2 if operation=='password_storage' else 1
        if reason!='verified' or count<minimum:raise ValueError('Invalid successful security receipt')
    elif verdict=='fail':
        if reason not in FAILURES[operation] or count<1 or reason=='reused_salt' and count<2:
            raise ValueError('Invalid failed security receipt')
    elif reason!='unavailable':raise ValueError('Invalid inconclusive security receipt')
    return dict(verdict=verdict,reason=reason,observations_checked=count)


class SecurityBroker(AuditBroker):
    """reader(operation, canaries) is trusted, bounded, guarded operator code.

    Password scope/defaults and log source inventory must be independently bound
    before issuing a pass. Log requests supply only canary values; the worker
    cannot choose Pods, history, library/profile, accounts or commands. Incomplete
    inspection must return inconclusive or raise; assertions/raw exception text
    are never automatically forwarded as application failures. Callback extras
    are stripped and never logged or exposed.
    """
    def __init__(self,reader,**bounds):
        for name in ('request_seconds','cleanup_seconds'):
            if name in bounds:positive(bounds[name],name)
        super().__init__(reader,**bounds)

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
                        request=receive(stream);operation=request.get('operation')
                        fields={'token','operation','canaries'} if operation=='log_canaries' else {'token','operation'}
                        if (set(request)!=fields or not isinstance(request.get('token'),str)
                                or not hmac.compare_digest(request['token'],self.token)):
                            send(stream,{'status':'refused'});continue
                        try:
                            canaries=request.get('canaries');request_values(operation,canaries)
                            if self.closing.is_set() or self.remaining<=0:raise ValueError('Security capability unavailable')
                            self.remaining-=1
                            receipt=project(operation,self.reader(operation,canaries))
                            if self.closing.is_set():raise ValueError('Security capability revoked')
                            send(stream,{'status':'observed','observation':receipt})
                        except Exception:
                            send(stream,{'status':'inconclusive'})
            except Exception:
                pass  # Request/exception data may be secrets; discard them.
            finally:
                self.connection=None;self.idle.set()

    def close(self):
        try:super().close()
        except AuditObservationError:raise SecurityObservationError('Security inspection cleanup incomplete') from None


def read_security(configuration,operation,*,canaries=None,timeout=45):
    """Request a fixed inspection and receive only its sanitized receipt."""
    request_values(operation,canaries)
    positive(timeout,'security request timeout')
    if timeout>60:raise ValueError('Security request timeout exceeds bound')
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(timeout)
    try:
        connection.connect(configuration['socket'])
        with connection.makefile('rwb') as stream:
            request=dict(token=configuration['token'],operation=operation)
            if operation=='log_canaries':request['canaries']=list(canaries)
            send(stream,request);response=receive(stream)
            if set(response)!={'status','observation'} or response['status']!='observed':
                raise SecurityObservationError('Security inspection unavailable')
            return project(operation,response['observation'],wire=True)
    except (OSError,ValueError,KeyError):
        raise SecurityObservationError('Security inspection unavailable') from None
    finally:connection.close()
