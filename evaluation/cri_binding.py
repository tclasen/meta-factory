"""Validate private CRI file attribution against anchored API declarations."""
import copy
import calendar
from datetime import datetime
import json
import re
import uuid

from .cri_staging import provisional_entry
from .log_retention import _file_identity
from .log_transport import source_binding
from .pod_history import PodIdentityHistory


MAX_INPUT_BYTES = 2 * 1024 * 1024
_ID = re.compile(r'[0-9a-f]{64}')
_TIME = re.compile(r'[1-9][0-9]{0,18}')
_INSPECT_TIME = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})')


class _Refusal(ValueError):
    def __init__(self, reason):
        self.reason = reason


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise _Refusal('identifier')
    return value


def _created(value):
    if not isinstance(value, str) or not _TIME.fullmatch(value) or int(value) > 2**63-1:
        raise _Refusal('timestamp')
    return int(value)


def _inspected_created(value):
    # crictl formats inspect timestamps for humans while list timestamps remain
    # decimal nanoseconds. Never use floats or datetime's truncated microseconds.
    if isinstance(value,str) and _TIME.fullmatch(value): return _created(value)
    match = _INSPECT_TIME.fullmatch(value) if isinstance(value,str) else None
    if match is None: raise _Refusal('timestamp')
    try:
        base = datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S')
        seconds = calendar.timegm(base.timetuple())
        zone = match[3]
        if zone != 'Z':
            hours, minutes = int(zone[1:3]), int(zone[4:6])
            if hours > 23 or minutes > 59 or zone == '-00:00': raise ValueError()
            seconds -= (1 if zone[0] == '+' else -1) * (hours*3600+minutes*60)
        result = seconds*1000000000 + int((match[2] or '').ljust(9,'0'))
        if not 0 < result <= 2**63-1: raise ValueError()
        return result
    except Exception:
        raise _Refusal('timestamp') from None


def _labels(value, expected):
    if not isinstance(value, dict) or any(value.get(key) != item for key, item in expected.items()):
        raise _Refusal('scope_labels')


def bind_cri_log_source(history, entry, node, snapshot, file_identity):
    """Return a private source projection, or None for an unknown declaration.

    Inputs are private trusted operator observations: anchored PodIdentityHistory,
    v1 Node, exact CRI list Container and PodSandbox plus inspect replies, and
    independently observed node/file identity. snapshot has exactly container,
    container_detail, sandbox and sandbox_detail fields. The supported runtime is
    containerd with the pinned crictl JSON encoding verified in local K3s checks.

    Caller verifies original Namespace UID, Node UID/runtime endpoint/peer, owner,
    both clocks and the exact node log path/device/inode before AND after obtaining
    these observations, then repeats verification through staging.bind's callback.
    This pure validator performs no IO, authenticity or lifetime checks itself.
    Runtime and filesystem names cannot invent an anchored API Pod/container.

    Known API index/CID conflicts and CID reuse across indices refuse attribution.
    A previously unseen API CID may be derived from matching runtime metadata,
    sandbox Pod labels, exact restart attempt and log path. Node name must already
    be anchored by the API declaration. Historical/deleted declarations remain
    eligible; this does not prove writer closure. No raw OCI/env/diagnostics or
    annotations are retained or returned. The returned IDs are private binder
    input, NEVER public receipts. No history is mutated, no runtime birth stream
    or bootstrap accounting is established; absence cannot pass acceptance.
    """
    try:
        if type(history) is not PodIdentityHistory:
            raise _Refusal('history')
        entry = provisional_entry(entry)
        declaration = history.runtime_declaration(entry)
        if declaration is None: return None
        if str(uuid.UUID(entry['pod_uid'])) != entry['pod_uid']:
            raise _Refusal('pod_uid')
        if (not isinstance(node, dict) or node.get('apiVersion') != 'v1' or node.get('kind') != 'Node'
                or not isinstance(snapshot, dict)
                or set(snapshot) != {'container', 'container_detail', 'sandbox', 'sandbox_detail'}
                or len(json.dumps(dict(node=node,snapshot=snapshot),allow_nan=False,ensure_ascii=False).encode()) > MAX_INPUT_BYTES):
            raise _Refusal('shape')
        node_meta = node.get('metadata')
        if (not isinstance(node_meta, dict) or not declaration['node_name']
                or node_meta.get('name') != declaration['node_name'] or node_meta.get('deletionTimestamp')):
            raise _Refusal('node_declaration')
        observed_file = _file_identity(file_identity)
        if node_meta.get('uid') != observed_file[0]:
            raise _Refusal('node_uid')
        runtime = node.get('status',{}).get('nodeInfo',{}).get('containerRuntimeVersion')
        if not isinstance(runtime,str) or not runtime.startswith('containerd://') or len(runtime) <= len('containerd://'):
            raise _Refusal('runtime')
        container, detail = snapshot['container'], snapshot['container_detail']
        sandbox, sandbox_detail = snapshot['sandbox'], snapshot['sandbox_detail']
        if not all(isinstance(value,dict) for value in (container,detail,sandbox,sandbox_detail)):
            raise _Refusal('shape')
        status, sandbox_status = detail.get('status'), sandbox_detail.get('status')
        info = detail.get('info')
        if not all(isinstance(value,dict) for value in (status,sandbox_status,info)):
            raise _Refusal('shape')
        identifier, sandbox_id = _identifier(container.get('id')), _identifier(sandbox.get('id'))
        if (status.get('id') != identifier or container.get('podSandboxId') != sandbox_id
                or sandbox_status.get('id') != sandbox_id or info.get('sandboxID') != sandbox_id):
            raise _Refusal('sandbox_link')
        expected_labels = {'io.kubernetes.pod.uid':entry['pod_uid'],
                           'io.kubernetes.pod.name':entry['pod_name'],
                           'io.kubernetes.pod.namespace':entry['namespace']}
        for value in (sandbox,sandbox_status):
            _labels(value.get('labels'),expected_labels)
        container_labels = dict(expected_labels,**{'io.kubernetes.container.name':entry['container_name']})
        for value in (container,status):
            _labels(value.get('labels'),container_labels)
            metadata = value.get('metadata')
            if (not isinstance(metadata,dict) or metadata.get('name') != entry['container_name']
                    or type(metadata.get('attempt')) is not int or metadata['attempt'] != entry['restart_index']
                    or metadata['attempt'] > 1000000
                    or value.get('state') not in ('CONTAINER_CREATED','CONTAINER_RUNNING','CONTAINER_EXITED')):
                raise _Refusal('container_attempt')
        if status['metadata'] != container['metadata']:
            raise _Refusal('container_metadata')
        sandbox_meta = sandbox.get('metadata')
        if (not isinstance(sandbox_meta,dict) or sandbox_meta.get('name') != entry['pod_name']
                or sandbox_meta.get('uid') != entry['pod_uid'] or sandbox_meta.get('namespace') != entry['namespace']
                or type(sandbox_meta.get('attempt')) is not int or not 0 <= sandbox_meta['attempt'] <= 1000000
                or sandbox_status.get('metadata') != sandbox_meta
                or any(value.get('state') not in ('SANDBOX_READY','SANDBOX_NOTREADY') for value in (sandbox,sandbox_status))):
            raise _Refusal('sandbox_metadata')
        container_created, sandbox_created = _created(container.get('createdAt')), _created(sandbox.get('createdAt'))
        if (_inspected_created(status.get('createdAt')) != container_created
                or _inspected_created(sandbox_status.get('createdAt')) != sandbox_created
                or sandbox_created > container_created):
            raise _Refusal('creation_order')
        expected_path = ('/var/log/pods/'+entry['namespace']+'_'+entry['pod_name']+'_'+entry['pod_uid']
                         +'/'+entry['container_name']+'/'+str(entry['restart_index'])+'.log')
        if status.get('logPath') != expected_path:
            raise _Refusal('log_path')
        source = source_binding({key:entry[key] for key in entry if key != 'restart_index'} |
                                dict(container_id='containerd://'+identifier,previous=False))
        known = declaration['known_instances']; index = entry['restart_index']
        if (index in known and known[index] != source['container_id']
                or any(value == source['container_id'] and prior != index for prior,value in known.items())):
            raise _Refusal('api_identity')
        return dict(source=source,namespace_binding=copy.deepcopy(declaration['namespace_binding']),
                    restart_index=index,role=declaration['role'],
                    node_name=declaration['node_name'],node_uid=observed_file[0],
                    file_identity=copy.deepcopy(file_identity),pod_deleted=declaration['deleted'],
                    api_pending=declaration['pending'],api_container_id_observed=index in known,
                    history_complete=False)
    except Exception as error:
        failure = ValueError('Private CRI log binding unavailable')
        failure.reason = error.reason if type(error) is _Refusal else 'input_or_history'
        raise failure from None
