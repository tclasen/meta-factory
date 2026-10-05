"""Bounded, parent-owned physical S3 object enumeration for an export scope."""
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
import uuid

from .evidence import atomic_json, kill_group, positive, utc_now
from .job_broker import JobObservationError, export_identity


def bucket_name(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', value)
            or '..' in value or '.-' in value or '-.' in value):
        raise ValueError('Invalid bound S3 bucket')
    return value


def private_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value: raise ValueError('Duplicate storage observation key')
            value[key] = item
        return value
    def constant(_): raise ValueError('Nonfinite storage observation')
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(value, dict): raise ValueError('Invalid storage observation')
    return value


class S3ListTransport:
    """Trusted AWS CLI prefix binds exact endpoint/config/credentials privately.

    Prefix must contain no secret values. Peer checks must independently verify
    endpoint identity and immutable private credential/config files. No CLI is
    provisioned here. Commands and raw keys/diagnostics are never logged.
    """
    def __init__(self, attempt, cli_prefix, *, check, cwd, max_output_bytes=2*1024*1024):
        if (not isinstance(cli_prefix, (list, tuple)) or not 1 <= len(cli_prefix) <= 24
                or any(not isinstance(item, str) or not item or '\x00' in item or len(item)>1024 for item in cli_prefix)
                or not callable(check) or type(max_output_bytes) is not int
                or not 1024 <= max_output_bytes <= 4*1024*1024):
            raise ValueError('Invalid independently bound storage client')
        self.attempt, self.prefix, self.check = attempt, tuple(cli_prefix), check
        self.cwd, self.max_output_bytes = Path(cwd), max_output_bytes

    def __call__(self, bucket, prefix, continuation, *, timeout):
        bucket_name(bucket); positive(timeout, 'storage read timeout')
        if (timeout>15 or not isinstance(prefix,str) or not prefix or '\x00' in prefix or len(prefix.encode())>1024
                or continuation is not None and (not isinstance(continuation,str) or not continuation
                    or '\x00' in continuation or len(continuation.encode())>4096)):
            raise ValueError('Invalid bounded storage request')
        label = 'storage-' + uuid.uuid4().hex
        directory = self.attempt.directory/label; directory.mkdir(mode=0o700)
        record = dict(started=utc_now(),outcome='incomplete',exit_code=None,stdout_bytes=0,stderr_bytes=0)
        process = None; started = time.monotonic(); output = bytearray(); value = None
        try:
            self.check(timeout+5)
            argv = [*self.prefix,'s3api','list-objects-v2','--bucket',bucket,'--prefix',prefix,
                    '--max-keys','1000','--no-paginate','--output','json','--no-cli-pager',
                    '--cli-connect-timeout','3','--cli-read-timeout','5']
            if continuation is not None:argv += ['--continuation-token',continuation]
            environment = dict(os.environ, AWS_MAX_ATTEMPTS='1', AWS_PAGER='', AWS_EC2_METADATA_DISABLED='true')
            process = subprocess.Popen(argv,cwd=self.cwd,env=environment,stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            with selectors.DefaultSelector() as selector:
                for stream, kind in ((process.stdout,'stdout'),(process.stderr,'stderr')):
                    os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,kind)
                while selector.get_map() or process.poll() is None:
                    remaining = timeout-(time.monotonic()-started)
                    if remaining<=0:record['outcome']='timeout';break
                    for key,_ in selector.select(min(remaining,.1)):
                        data = os.read(key.fd,65536)
                        if not data:selector.unregister(key.fileobj);continue
                        record[key.data+'_bytes'] += len(data)
                        if record['stdout_bytes']+record['stderr_bytes']>self.max_output_bytes:
                            record['outcome']='output_limit';break
                        if key.data=='stdout':output.extend(data)
                    if record['outcome']=='output_limit':break
                else:
                    if process.returncode!=0:record['outcome']='command_failed'
                    else:
                        value = private_json(output.decode('utf-8'))
                        self.check(5);record['outcome']='observed'
        except BaseException as error:
            record.update(outcome='interrupted' if not isinstance(error,Exception) else 'transport_incomplete',
                          error_type=type(error).__name__)
            if not isinstance(error,Exception):raise
        finally:
            if process is not None:
                kill_group(process);record['exit_code']=process.returncode
                process.stdout.close();process.stderr.close()
            record.update(ended=utc_now(),elapsed_seconds=time.monotonic()-started)
            atomic_json(directory/'result.json',record)
            self.attempt.emit('controller','storage.read.finished',dict(record,label=label))
        if record['outcome']!='observed':raise JobObservationError('Storage observation unavailable')
        return value


class S3ArtifactCounter:
    """Enumerate physical current objects in an independently reviewed export prefix.

    Prefix mapping must include only published artifacts for this export, not
    staging/evidence/unrelated objects. It is not selected from DB artifact rows.
    Listing does not establish version history or an atomic DB/storage snapshot.
    """
    def __init__(self, transport, bucket, prefix_for_export, *, max_pages=8, check,
                 monotonic=time.monotonic):
        bucket_name(bucket)
        if (not callable(transport) or not callable(prefix_for_export) or not callable(check)
                or type(max_pages) is not int or not 1<=max_pages<=32):
            raise ValueError('Reviewed bounded artifact scope required')
        self.transport,self.bucket,self.scope = transport,bucket,prefix_for_export
        self.max_pages,self.check,self.monotonic = max_pages,check,monotonic

    def __call__(self, export_id, *, timeout):
        export_identity(export_id);positive(timeout,'artifact enumeration timeout')
        if timeout>15:raise ValueError('Artifact enumeration exceeds bound')
        prefix = self.scope(export_id)
        if (not isinstance(prefix,str) or export_id not in prefix or '\x00' in prefix
                or len(prefix.encode())>1024):
            raise JobObservationError('Independent artifact scope unavailable')
        deadline=self.monotonic()+timeout;token=None;tokens=set();keys=set()
        for _ in range(self.max_pages):
            remaining=deadline-self.monotonic()
            if remaining<=0:raise JobObservationError('Artifact enumeration deadline')
            self.check(remaining+5)
            page=self.transport(self.bucket,prefix,token,timeout=remaining)
            self.check(5)
            if self.monotonic()>=deadline:raise JobObservationError('Artifact enumeration deadline')
            if (not isinstance(page,dict) or page.get('Name')!=self.bucket or page.get('Prefix')!=prefix
                    or type(page.get('IsTruncated')) is not bool
                    or type(page.get('KeyCount')) is not int or not 0<=page['KeyCount']<=1000
                    or not isinstance(page.get('Contents',[]),list)
                    or len(page.get('Contents',[]))!=page['KeyCount']):
                raise JobObservationError('Storage scope or page observation changed')
            for item in page.get('Contents',[]):
                key=item.get('Key') if isinstance(item,dict) else None
                if (not isinstance(key,str) or not key.startswith(prefix) or len(key.encode())>1024
                        or key in keys or '\x00' in key):
                    raise JobObservationError('Ambiguous physical artifact listing')
                keys.add(key)
            if not page['IsTruncated']:
                if page.get('NextContinuationToken') is not None:
                    raise JobObservationError('Unexpected storage continuation')
                return len(keys)
            token=page.get('NextContinuationToken')
            if (not isinstance(token,str) or not token or len(token.encode())>4096
                    or '\x00' in token or token in tokens):
                raise JobObservationError('Invalid storage continuation')
            tokens.add(token)
        raise JobObservationError('Artifact enumeration page limit')
