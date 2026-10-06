"""Bounded private unfiltered Pod watch windows; not full log-history proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
from urllib.parse import urlencode
import uuid

from .evidence import atomic_json, kill_group, positive, utc_now
from .log_transport import source_binding


MAX_EVENT_BYTES = 1024 * 1024
MAX_WINDOW_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 4096


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('Ambiguous private watch object')
        result[key] = value
    return result


def _version(value):
    if not isinstance(value, str) or not value or '\x00' in value or len(value.encode()) > 512:
        raise ValueError('Private watch resource version required')
    return value


def watch_event(raw, namespace):
    """Validate framing/scope privately; no raw error payload is projected."""
    value = json.loads(raw, object_pairs_hook=_unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite private watch value')))
    if not isinstance(value, dict) or set(value) != {'type', 'object'}:
        raise ValueError('Invalid private watch event')
    if value['type'] not in ('ADDED', 'MODIFIED', 'DELETED', 'BOOKMARK'):
        raise ValueError('Private watch error or unknown event')
    obj = value['object']
    if not isinstance(obj, dict) or obj.get('apiVersion') != 'v1' or obj.get('kind') != 'Pod':
        raise ValueError('Invalid private Pod watch object')
    metadata = obj.get('metadata')
    if not isinstance(metadata, dict): raise ValueError('Invalid private watch metadata')
    _version(metadata.get('resourceVersion'))
    if value['type'] != 'BOOKMARK':
        if (metadata.get('namespace') != namespace or not isinstance(metadata.get('name'), str)
                or not metadata['name'] or len(metadata['name']) > 253
                or not isinstance(metadata.get('uid'), str) or not metadata['uid']
                or '\x00' in metadata['uid'] or len(metadata['uid'].encode()) > 512):
            raise ValueError('Private watch scope identity unavailable')
        source_binding(dict(namespace=namespace, pod_name=metadata['name'], pod_uid=metadata['uid'],
                            container_name='validation', container_id='validation', previous=False))
    return value


class PodWatchTransport:
    """consume(event) is trusted, bounded parent code receiving private objects.

    check(binding, reserve) must independently verify API, namespace UID, owner,
    sandbox and original deadlines before and after the window. API watch errors,
    lost anchors, malformed/truncated data and callback failure are incomplete.
    A normal closed window does not establish continuous watch intervals, archived
    log bytes, rotation coverage or a complete namespace/history acceptance claim.
    """
    def __init__(self, attempt, peer_prefix, binding, *, resource_version, check, cwd):
        if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
                or any(not isinstance(v, str) or not v or '\x00' in v or len(v) > 1024 for v in peer_prefix)):
            raise ValueError('Trusted private watch prefix required')
        if (not isinstance(binding, dict) or set(binding) != {'name', 'uid'}
                or not isinstance(binding['name'], str)
                or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', binding['name'])
                or not isinstance(binding['uid'], str) or not binding['uid']
                or '\x00' in binding['uid'] or len(binding['uid'].encode()) > 512 or not callable(check)):
            raise ValueError('Independent private namespace watch binding required')
        self.attempt, self.prefix, self.binding = attempt, tuple(peer_prefix), copy.deepcopy(binding)
        self.version, self.check, self.cwd = _version(resource_version), check, Path(cwd)
        if self.version == '0': raise ValueError('Anchored private watch resource version required')

    def __call__(self, consume, *, timeout=15, window_id=None):
        positive(timeout, 'Pod watch timeout')
        if timeout > 30 or not callable(consume): raise ValueError('Bounded private watch consumer required')
        if window_id is None: window_id = 'pod-watch-'+uuid.uuid4().hex
        if not isinstance(window_id, str) or not re.fullmatch(r'pod-watch-[0-9a-f]{32}', window_id):
            raise ValueError('Private watch window identity required')
        started = time.monotonic()
        record = dict(started=utc_now(), outcome='incomplete', events=0, stdout_bytes=0, stderr_bytes=0,
                      source_verified_before=False, source_verified_after=False, client_group_absent=False,
                      binding_sha256=hashlib.sha256(json.dumps(self.binding, sort_keys=True).encode()).hexdigest(),
                      anchor_sha256=hashlib.sha256(self.version.encode()).hexdigest(),
                      client_prefix_sha256=hashlib.sha256(json.dumps(self.prefix).encode()).hexdigest())
        directory = self.attempt.directory / window_id
        directory.mkdir(mode=0o700)
        record['window_id'] = window_id
        process, buffer = None, b''
        def verify(reserve):
            if self.check(copy.deepcopy(self.binding), reserve) is not True:
                raise ValueError('Private watch identity or lifetime unavailable')
        try:
            verify(timeout+5); record['source_verified_before'] = True
            query = urlencode(dict(watch='true', resourceVersion=self.version, allowWatchBookmarks='true', timeoutSeconds=max(1, int(timeout)-5)))
            path = '/api/v1/namespaces/'+self.binding['name']+'/pods?'+query
            process = subprocess.Popen([*self.prefix, 'get', '--raw='+path, '--request-timeout='+str(timeout)+'s'],
                                       cwd=self.cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            record['client_group'] = process.pid
            with selectors.DefaultSelector() as selector:
                for pipe, kind in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
                    os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, kind)
                while selector.get_map() or process.poll() is None:
                    remaining = timeout-(time.monotonic()-started)
                    if remaining <= 0: raise ValueError('Private watch timeout')
                    for key, _ in selector.select(min(remaining, .1)):
                        data = os.read(key.fd, 65536)
                        if not data: selector.unregister(key.fileobj); continue
                        record[key.data+'_bytes'] += len(data)
                        if key.data == 'stderr':
                            if record['stderr_bytes'] > 65536: raise ValueError('Private watch diagnostic limit')
                            continue
                        if record['stdout_bytes'] > MAX_WINDOW_BYTES: raise ValueError('Private watch output limit')
                        buffer += data
                        while b'\n' in buffer:
                            raw, buffer = buffer.split(b'\n', 1)
                            if not raw or len(raw) > MAX_EVENT_BYTES or record['events'] >= MAX_EVENTS:
                                raise ValueError('Private watch event bound')
                            event = watch_event(raw, self.binding['name'])
                            consume(event)
                            record['events'] += 1
                        if len(buffer) > MAX_EVENT_BYTES: raise ValueError('Private watch event bound')
            if process.returncode != 0 or buffer: raise ValueError('Private watch incomplete command or frame')
            record['outcome'] = 'watch_window_closed'
        except BaseException as error:
            record.update(outcome='interrupted' if not isinstance(error, Exception) else 'incomplete', error_type=type(error).__name__)
            if not isinstance(error, Exception): raise
        finally:
            if process:
                kill_group(process); record['exit_code'] = process.returncode
                for pipe in (process.stdout, process.stderr): pipe.close()
                try: os.killpg(process.pid, 0)
                except ProcessLookupError: record['client_group_absent'] = True
                else: record['outcome'] = 'incomplete'
            if record['source_verified_before']:
                try: verify(5); record['source_verified_after'] = True
                except Exception as error:
                    record['source_check_error_type'] = type(error).__name__
                    if record['outcome'] != 'interrupted': record['outcome'] = 'incomplete'
            record.update(ended=utc_now(), elapsed_seconds=time.monotonic()-started)
            atomic_json(directory / 'result.json', record)
            self.attempt.emit('controller', 'pod.watch.finished', record)
        return record
