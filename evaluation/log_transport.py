"""Private read-only Kubernetes log transport for operator-bound canary checks.

Only fixed kubectl logs snapshots are requested. No arbitrary grader commands,
raw log files, connection diagnostics or secret values enter evidence. A complete
snapshot does not establish complete application source/history coverage.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
import uuid

from .evidence import atomic_json,kill_group,positive,utc_now
from .secret_scan import DEFAULT_BYTES,canary_patterns,binary_canary_patterns,scan_secret_chunks


SOURCE_FIELDS = {'namespace','pod_name','pod_uid','container_name','container_id','previous'}


def source_binding(value):
    if not isinstance(value,dict) or set(value)!=SOURCE_FIELDS:
        raise ValueError('Complete operator log source binding required')
    for key in ('namespace','container_name'):
        if not isinstance(value[key],str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',value[key]):
            raise ValueError('Invalid bound log source name')
    pod=value['pod_name']
    if (not isinstance(pod,str) or len(pod)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in pod.split('.'))):
        raise ValueError('Invalid bound log source name')
    for key in ('pod_uid','container_id'):
        if not isinstance(value[key],str) or not value[key] or '\x00' in value[key] or len(value[key].encode())>512:
            raise ValueError('Immutable log source identity required')
    if type(value['previous']) is not bool:
        raise ValueError('Explicit current or previous log source required')
    return copy.deepcopy(value)


class LogTransport:
    """One fixed client/source with independently verified lifetime and identity.

    check(source,reserve) must return exactly True after observing the original
    Pod UID, selected current/previous container ID and active grading guard;
    reserve includes client termination/identity-check time. Prefix is trusted
    operator input for pinned kubectl/configuration, never builder/worker input.
    It must not contain credentials. Only parent-side canaries are accepted.
    """
    def __init__(self,attempt,peer_prefix,source,*,check,cwd,max_output_bytes=DEFAULT_BYTES):
        if (not isinstance(peer_prefix,(list,tuple)) or not 1<=len(peer_prefix)<=24
                or any(not isinstance(value,str) or not value or '\x00' in value or len(value)>1024 for value in peer_prefix)):
            raise ValueError('Invalid trusted log client prefix')
        if not callable(check):raise ValueError('Independent log source/guard check required')
        if type(max_output_bytes) is not int or not 1<=max_output_bytes<=64*1024*1024:
            raise ValueError('Invalid log output bound')
        self.attempt,self.prefix,self.source=attempt,tuple(peer_prefix),source_binding(source)
        self.check,self.cwd,self.max_output_bytes=check,Path(cwd),max_output_bytes

    def __call__(self,canaries=None,*,binary_values=None,timeout=15):
        positive(timeout,'log command timeout')
        if timeout>30:raise ValueError('Log command timeout exceeds bound')
        # Refuse unsupported controls before client creation or evidence writes.
        if canaries is None and binary_values is None:
            raise ValueError('Known log canaries required')
        if canaries is not None:canary_patterns(canaries)
        if binary_values is not None:binary_canary_patterns(binary_values)
        source=copy.deepcopy(self.source)
        started=time.monotonic()
        record=dict(started=utc_now(),outcome='incomplete',exit_code=None,stdout_bytes=0,stderr_bytes=0,
            source_sha256=hashlib.sha256(json.dumps(source,sort_keys=True).encode()).hexdigest(),
            client_prefix_sha256=hashlib.sha256(json.dumps(self.prefix).encode()).hexdigest(),
            client_group_absent=False,source_verified_before=False,source_verified_after=False)
        label='logs-'+uuid.uuid4().hex;directory=self.attempt.directory/label;directory.mkdir(mode=0o700)
        self.attempt.emit('controller','logs.command.started',dict(label=label,**record))
        process=None;client_complete=False;diagnostic_limit=65536
        def verify(reserve):
            if self.check(copy.deepcopy(source),reserve) is not True:
                raise RuntimeError('Log source/guard identity unavailable')
        def chunks():
            nonlocal process,client_complete
            verify(timeout+5);record['source_verified_before']=True
            argv=[*self.prefix,'logs','--namespace='+source['namespace'],source['pod_name'],
                '--container='+source['container_name'],'--timestamps=true','--tail=-1',
                '--previous='+str(source['previous']).lower(),'--request-timeout='+str(timeout)+'s']
            process=subprocess.Popen(argv,cwd=self.cwd,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            record['client_group']=process.pid
            with selectors.DefaultSelector() as selector:
                for stream,kind in ((process.stdout,'stdout'),(process.stderr,'stderr')):
                    os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,kind)
                while selector.get_map() or process.poll() is None:
                    remaining=timeout-(time.monotonic()-started)
                    if remaining<=0:
                        record['client_outcome']='timeout';raise RuntimeError('Private log collection timed out')
                    for key,_ in selector.select(min(remaining,.1)):
                        data=os.read(key.fd,65536)
                        if not data:selector.unregister(key.fileobj);continue
                        record[key.data+'_bytes']+=len(data)
                        if key.data=='stderr':
                            if record['stderr_bytes']>diagnostic_limit:
                                record['client_outcome']='diagnostic_limit';raise RuntimeError('Private log diagnostic limit')
                            # kubectl stderr is private client diagnostics, not a log
                            # source. Kubernetes merges application stdout/stderr in
                            # the stdout log stream. Never persist diagnostics.
                            continue
                        yield data
                if process.returncode!=0:
                    record['client_outcome']='command_failed';raise RuntimeError('Private log client failed')
                client_complete=True;record['client_outcome']='observed'
        stream=chunks()
        try:
            receipt=scan_secret_chunks(stream,canaries,binary_values=binary_values,max_bytes=self.max_output_bytes)
            record['scan']=receipt
            record['outcome']='canary_detected' if receipt['canary_present'] else (
                'observed_clean' if receipt['complete'] and client_complete else 'incomplete')
        except BaseException as error:
            record.update(outcome='interrupted' if not isinstance(error,Exception) else 'incomplete',error_type=type(error).__name__)
            if not isinstance(error,Exception):raise
        finally:
            stream.close()
            if process is not None:
                kill_group(process);record['exit_code']=process.returncode
                for pipe in (process.stdout,process.stderr):pipe.close()
                try:os.killpg(process.pid,0)
                except ProcessLookupError:record['client_group_absent']=True
                else:
                    record['client_group_absent']=False
                    record['outcome']='incomplete'
            if record['source_verified_before']:
                try:
                    verify(5);record['source_verified_after']=True
                except Exception as error:
                    record['source_check_error_type']=type(error).__name__
                    if record['outcome']!='interrupted':record['outcome']='incomplete'
            record.update(ended=utc_now(),elapsed_seconds=time.monotonic()-started)
            atomic_json(directory/'result.json',record)
            self.attempt.emit('controller','logs.command.finished',dict(label=label,**record))
        return record
