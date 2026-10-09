"""Owned grading transport to the VM's existing loopback application publication.

The shared protocol must select this adapter explicitly. A direct HTTP response
uses the original publication; only a refused/reset/timed-out connection starts
an opaque fixed-destination VM bridge. Neither observation grants acceptance.
"""
import hashlib
import http.client
import ipaddress
import json
import math
from pathlib import Path
import re
import selectors
import subprocess
import time
import uuid

from .evidence import atomic_json, kill_group
from .verdicts import Inconclusive
from .watchdog import NAME


STOP_SOURCE = '''import json,os,signal,sys
v=json.loads(sys.argv[1]);p='/proc/'+str(v['pid'])
try:
 ticks=open(p+'/stat').read().rsplit(')',1)[1].split()[19]
 assert ticks==v['start_ticks'] and os.stat(p).st_uid==v['uid'] and v['uid']==os.getuid()
 os.kill(v['pid'],signal.SIGTERM)
except FileNotFoundError:pass
print(json.dumps(dict(outcome='owned_relay_stop_requested')))
'''


class LoopbackBridge:
    def __init__(self, attempt, sandbox, *, host_port, lifetime_check,
                 monotonic_deadline, wall_deadline, cleanup_lifetime_check=None):
        if (not NAME.fullmatch(sandbox.name) or '-grader-' not in sandbox.name
                or type(host_port) is not int or not 1024<=host_port<=65535
                or not callable(lifetime_check)
                or (cleanup_lifetime_check is not None and not callable(cleanup_lifetime_check))
                or any(type(v) not in (int,float) or not math.isfinite(v) or v<=0
                       for v in (monotonic_deadline,wall_deadline))):
            raise ValueError('Owned grading publication and lifetime required')
        self.attempt, self.sandbox = attempt, sandbox
        self.port, self.check = host_port, lifetime_check
        self.cleanup_check = lifetime_check if cleanup_lifetime_check is None else cleanup_lifetime_check
        self.deadline, self.wall_deadline = monotonic_deadline, wall_deadline
        self.nonce = uuid.uuid4().hex
        self.process = self.binding = None
        self.closed = self.started = False
        self.report = dict(outcome='bridge_not_started', nonce=self.nonce,
                           payloads_logged=False, application_modified=False)

    def start(self):
        if self.started or self.closed:
            raise ValueError('One bridge preparation per grading deployment')
        self.started = True
        self.check(15)
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        try:
            connection.request('HEAD','/')
            response = connection.getresponse()
            self.report.update(outcome='direct_http_observed',status=response.status,
                               mode='direct_http',resources_created=False)
            self.check(0)
            atomic_json(self.attempt.directory/'loopback-bridge.json',self.report)
            return
        except (ConnectionRefusedError,ConnectionResetError,TimeoutError):
            pass
        finally:
            connection.close()
        remaining = min(self.deadline-time.monotonic(),self.wall_deadline-time.time())
        self.check(15)
        if not 15<remaining<=26*3600:
            raise Inconclusive('Bridge lifetime unavailable')
        config = dict(nonce=self.nonce,max_seconds=remaining,expires_at=self.wall_deadline)
        source = Path(__file__).with_name('loopback_bridge_probe.py').read_text()
        self.report.update(mode='vm_loopback_bridge',resources_created=True,
                           probe_sha256=hashlib.sha256(source.encode()).hexdigest())
        self.process = subprocess.Popen(self.sandbox.exec_argv(['python3','-c',source,json.dumps(config)]),
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        raw = bytearray();diagnostics = 0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdout,selectors.EVENT_READ,'stdout')
                selector.register(self.process.stderr,selectors.EVENT_READ,'stderr')
                until=time.monotonic()+10
                while b'\n' not in raw:
                    if time.monotonic()>=until:
                        raise TimeoutError('Bridge readiness deadline')
                    for key,_ in selector.select(.1):
                        chunk=key.fileobj.read1(8193)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        elif key.data=='stdout':
                            raw.extend(chunk)
                        else:
                            diagnostics+=len(chunk)
                        if len(raw)+diagnostics>8192:
                            raise ValueError('Bridge readiness bound')
                    if not selector.get_map() and b'\n' not in raw:
                        raise Inconclusive('Bridge readiness unavailable')
            binding=json.loads(raw)
            address=ipaddress.ip_address(binding['address'])
            if (binding.get('outcome')!='owned_tcp_relay_ready' or binding.get('nonce')!=self.nonce
                    or type(binding.get('pid')) is not int or binding['pid']<=1
                    or type(binding.get('uid')) is not int or binding['uid']<0
                    or not isinstance(binding.get('start_ticks'),str)
                    or not re.fullmatch('[0-9]{1,24}',binding['start_ticks'])
                    or binding.get('port')!=8080 or binding.get('upstream')!='127.0.0.1:8080'
                    or not address.is_private or address.is_loopback or address.is_link_local
                    or address.is_unspecified or address.is_multicast):
                raise ValueError('Owned fixed-destination bridge identity unavailable')
            self.binding=binding
            self.check(0)
            self.report.update(outcome='loopback_bridge_ready',binding=binding)
        except Exception as error:
            self.report.update(outcome='loopback_bridge_incomplete',error_type=type(error).__name__)
            raise
        finally:
            atomic_json(self.attempt.directory/'loopback-bridge.json',self.report)

    def close(self):
        if self.closed:
            return
        self.closed=True
        try:
            if self.process is None:
                self.report['cleanup_verified']=True
                return
            if self.binding is None:
                raise Inconclusive('Bridge identity missing; sandbox cleanup required')
            # A finished transport must still supply its validated native stop
            # receipt. Never signal a possibly reused PID after it has exited.
            if self.process.poll() is None:
                if self.cleanup_check(12) is not True:
                    raise Inconclusive('Bridge cleanup lifetime unavailable')
                result=subprocess.run(self.sandbox.exec_argv(['python3','-c',STOP_SOURCE,json.dumps(self.binding)]),
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                if result.returncode or len(result.stdout)+len(result.stderr)>8192:
                    raise Inconclusive('Bridge stop request unavailable')
                self.process.wait(timeout=10)
            out,err=self.process.communicate(timeout=2)
            if self.process.returncode or len(out)+len(err)>8192:
                raise Inconclusive('Bridge stop receipt unavailable')
            value=json.loads(out)
            counts=value['counts']
            if (value.get('outcome')!='owned_tcp_relay_stopped' or value.get('nonce')!=self.nonce
                    or set(counts)!={'connections','completed','errors','bytes','active'}
                    or any(type(v) is not int or v<0 for v in counts.values())
                    or counts['active']!=0):
                raise Inconclusive('Bridge connections unsettled')
            self.report.update(cleanup_verified=True,counts=counts)
        except Exception as error:
            self.report.update(cleanup_verified=False,cleanup_error_type=type(error).__name__)
            raise
        finally:
            if self.process is not None:
                kill_group(self.process)
                for stream in (self.process.stdout,self.process.stderr):stream.close()
            atomic_json(self.attempt.directory/'loopback-bridge.json',self.report)
