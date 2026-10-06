"""Private bounded runtime metadata waiting for independent API/file admission."""
import copy
import json
import os
import threading
import time
import uuid

from .cri_binding import MAX_INPUT_BYTES, _created, _identifier, _inspected_created, _labels
from .cri_runtime_event import EVENT_TYPES, _event_snapshot
from .cri_staging import provisional_entry, _key
from .evidence import positive
from .log_retention import _file_identity
from .pod_history import PodIdentityHistory


MAX_ENTRIES = 128
MAX_OPERATIONS = 4096


class PrivateCRIRuntimeEventBuffer:
    """Hold minimal creation metadata while API declarations or files are pending.

    check(reserve) authenticates the original Namespace/Node/runtime/owner and
    clocks before/after every operation. Events must come from an independently
    authenticated uninterrupted stream. This class performs no IO and cannot
    detect missing stream events; callers invalidate it on transport interruption.
    Foreign namespaces and sandbox events consume the operation quota but cannot
    create container records. Scoped container events require observed creation
    followed by start/stop/delete in order; duplicates, missing births, immutable
    drift, reuse, guard failure and bounds permanently release all metadata.

    event_for returns a PRIVATE minimal creation body only after an original API
    declaration agrees. It is not file attribution: use capture_event with an
    independently authenticated held file. Deletion preserves previously observed
    creation metadata; it never invents attribution or proves writers finished.
    No relist/rebaseline, API mutation, raw diagnostics/annotations/resources or
    public identities. Every receipt says history_complete=False. Missing births,
    bootstrap, source coverage and API/time/writer fences remain unresolved.
    """
    def __init__(self, history, *, node_uid, node_name, check, deadline):
        positive(deadline, 'Private runtime buffer deadline')
        if type(history) is not PodIdentityHistory or not callable(check):
            raise ValueError('Private runtime buffer inputs required')
        history._owned()
        _file_identity(dict(node_uid=node_uid, device=0, inode=1))
        provisional_entry(dict(namespace=history._binding['name'], pod_name=node_name,
            pod_uid='validation', container_name='validation', restart_index=0))
        self._history, self._binding = history, copy.deepcopy(history._binding)
        self._node, self._name, self._check, self._deadline = node_uid, node_name, check, deadline
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._records, self._cids, self._sandboxes = {}, {}, {}
        self._operations, self._foreign, self._sandbox_events = 0, 0, 0
        self._valid = True
        try: self._verify()
        except BaseException as error:
            self._discard()
            if not isinstance(error, Exception): raise
            raise ValueError('Private runtime buffer unavailable') from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private runtime buffer owner unavailable')

    def _verify(self):
        if (not self._valid or time.monotonic()+5 >= self._deadline
                or self._check(5) is not True or not self._history.summary()['valid']
                or self._history._binding != self._binding):
            raise ValueError('Private runtime buffer lifetime unavailable')

    def _operation(self):
        self._verify()
        if self._operations >= MAX_OPERATIONS:
            raise ValueError('Private runtime buffer bound')
        self._operations += 1

    def _discard(self):
        self._valid = False
        self._records.clear(); self._cids.clear(); self._sandboxes.clear()

    def accept(self, event):
        """Admit an observed event; return counts only, never runtime identities."""
        self._owned()
        with self._lock:
            try:
                self._operation()
                event = copy.deepcopy(event)
                if (not isinstance(event, dict)
                        or len(json.dumps(event, allow_nan=False).encode()) > MAX_INPUT_BYTES
                        or event.get('containerEventType') not in EVENT_TYPES):
                    raise ValueError('Private runtime buffer shape')
                cid, timestamp = _identifier(event.get('containerId')), _created(event.get('createdAt'))
                sandbox = event.get('podSandboxStatus')
                if not isinstance(sandbox, dict) or not isinstance(sandbox.get('metadata'), dict):
                    raise ValueError('Private runtime buffer scope')
                metadata = sandbox['metadata']
                if metadata.get('namespace') != self._binding['name']:
                    self._foreign += 1; self._verify(); return self.summary()
                sid = _identifier(sandbox.get('id'))
                if cid == sid:
                    self._sandbox_events += 1; self._verify(); return self.summary()
                if sandbox.get('state') not in ('SANDBOX_READY','SANDBOX_NOTREADY'):
                    raise ValueError('Private runtime buffer sandbox state')
                if str(uuid.UUID(metadata.get('uid'))) != metadata['uid']:
                    raise ValueError('Private runtime buffer Pod identity')
                pod_labels = {'io.kubernetes.pod.uid':metadata['uid'],
                    'io.kubernetes.pod.name':metadata.get('name'),
                    'io.kubernetes.pod.namespace':metadata['namespace']}
                _labels(sandbox.get('labels'), pod_labels)
                if type(metadata.get('attempt')) is not int or not 0 <= metadata['attempt'] <= 1000000:
                    raise ValueError('Private runtime buffer sandbox attempt')
                sandbox_created = _inspected_created(sandbox.get('createdAt'))
                pod = (metadata['namespace'], metadata.get('name'), metadata['uid'],
                       metadata['attempt'], sandbox_created)
                if sid in self._sandboxes and self._sandboxes[sid] != pod:
                    raise ValueError('Private runtime buffer sandbox reuse')
                kind = event['containerEventType']
                existing_key = self._cids.get(cid)
                if kind == 'CONTAINER_DELETED_EVENT':
                    if existing_key is None:
                        raise ValueError('Private runtime buffer missing birth')
                    record = self._records[existing_key]
                    if record['sandbox_id'] != sid or record['pod'] != pod:
                        raise ValueError('Private runtime buffer tombstone scope')
                else:
                    snapshot, _ = _event_snapshot(event)
                    status = snapshot['container_detail']['status']
                    cm = status.get('metadata')
                    if not isinstance(cm, dict): raise ValueError('Private runtime buffer container')
                    entry = provisional_entry(dict(namespace=metadata['namespace'],
                        pod_name=metadata.get('name'), pod_uid=metadata['uid'],
                        container_name=cm.get('name'), restart_index=cm.get('attempt')))
                    if entry['restart_index'] > 1000000:
                        raise ValueError('Private runtime buffer attempt bound')
                    labels = dict(pod_labels, **{'io.kubernetes.container.name':entry['container_name']})
                    _labels(status.get('labels'), labels)
                    expected = ('/var/log/pods/'+entry['namespace']+'_'+entry['pod_name']+'_'+entry['pod_uid']
                                +'/'+entry['container_name']+'/'+str(entry['restart_index'])+'.log')
                    if status.get('logPath') != expected or status.get('state') not in ('CONTAINER_CREATED','CONTAINER_RUNNING','CONTAINER_EXITED'):
                        raise ValueError('Private runtime buffer container identity')
                    created = _inspected_created(status.get('createdAt'))
                    if sandbox_created > created:
                        raise ValueError('Private runtime buffer creation order')
                    immutable = dict(id=cid, metadata=dict(name=entry['container_name'],attempt=entry['restart_index']),
                        labels=labels, logPath=expected, createdAt=str(created))
                    key = _key(entry)
                    if kind == 'CONTAINER_CREATED_EVENT':
                        if key in self._records or existing_key is not None or len(self._records) >= MAX_ENTRIES:
                            raise ValueError('Private runtime buffer reuse or bound')
                        minimal_sandbox = dict(id=sid, metadata={k:metadata[k] for k in ('name','namespace','uid','attempt')},
                            labels=pod_labels, createdAt=str(sandbox_created), state=sandbox.get('state'))
                        body = dict(containerId=cid, containerEventType=kind, createdAt=str(timestamp),
                            podSandboxStatus=minimal_sandbox, containersStatuses=[dict(immutable,state=status['state'])])
                        record = dict(entry=entry, birth=body, immutable=immutable, sandbox_id=sid,
                            pod=pod, kind=kind, timestamp=timestamp)
                        self._records[key] = record; self._cids[cid] = key; self._sandboxes[sid] = pod
                    else:
                        if existing_key != key or key not in self._records:
                            raise ValueError('Private runtime buffer missing birth')
                        record = self._records[key]
                        if record['immutable'] != immutable or record['sandbox_id'] != sid or record['pod'] != pod:
                            raise ValueError('Private runtime buffer immutable drift')
                if kind != 'CONTAINER_CREATED_EVENT':
                    prior = EVENT_TYPES.index(record['kind'])
                    if EVENT_TYPES.index(kind) != prior+1 or timestamp < record['timestamp']:
                        raise ValueError('Private runtime buffer lifecycle gap')
                    record.update(kind=kind, timestamp=timestamp)
                self._verify()
                return self.summary()
            except BaseException as error:
                self._discard()
                if not isinstance(error, Exception): raise
                raise ValueError('Private runtime buffer unavailable') from None

    def event_for(self, entry):
        """Return a private creation copy only for an agreeing API declaration."""
        self._owned()
        with self._lock:
            try:
                self._operation()
                entry = provisional_entry(entry)
                if entry['namespace'] != self._binding['name']:
                    raise ValueError('Private runtime buffer lookup scope')
                record = self._records.get(_key(entry))
                declaration = self._history.runtime_declaration(entry)
                if record is None or declaration is None:
                    self._verify(); return None
                if declaration['node_name'] != self._name:
                    raise ValueError('Private runtime buffer Node declaration')
                known = declaration['known_instances']; index = entry['restart_index']
                cid = 'containerd://'+record['immutable']['id']
                if (index in known and known[index] != cid
                        or any(i != index and v == cid for i,v in known.items())):
                    raise ValueError('Private runtime buffer API conflict')
                self._verify()
                return copy.deepcopy(record['birth'])
            except BaseException as error:
                self._discard()
                if not isinstance(error, Exception): raise
                raise ValueError('Private runtime buffer unavailable') from None

    def summary(self):
        self._owned()
        with self._lock:
            return dict(outcome='private_cri_runtime_event_buffer', valid=self._valid,
                entries=len(self._records), operations=self._operations,
                foreign_events=self._foreign, sandbox_events=self._sandbox_events,
                deleted_entries=sum(r['kind']=='CONTAINER_DELETED_EVENT' for r in self._records.values()),
                metadata_released=not self._valid, history_complete=False)

    def close(self):
        self._owned()
        with self._lock:
            self._discard()
            return self.summary()
