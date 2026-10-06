"""Validate private bundled CRI event metadata; deletion needs prior attribution."""
import copy
import json

from .cri_binding import (MAX_INPUT_BYTES, _created, _identifier,
                          _inspected_created, bind_cri_log_source)


EVENT_TYPES = ('CONTAINER_CREATED_EVENT', 'CONTAINER_STARTED_EVENT',
               'CONTAINER_STOPPED_EVENT', 'CONTAINER_DELETED_EVENT')


def bind_cri_event_log_source(history, entry, node, event, file_identity):
    """Return a private file projection from an authenticated event's statuses.

    The caller authenticates the original runtime socket/peer, Node, Namespace,
    owner, clocks and held file before/after admission. Bundled ContainerStatus
    and PodSandboxStatus describe one observed runtime event, not independent
    list/inspect RPC replies. This function normalizes their encoding for the
    existing anchored-API/file validator; it performs no IO or authentication.

    CREATED/STARTED/STOPPED require exactly one status for the event CID. The
    event timestamp cannot precede that container's or sandbox's creation.
    DELETED returns None: the runtime can omit the deleted container's status,
    so a tombstone cannot invent file attribution. Use previously independently
    captured metadata instead. None never means clean/complete collection.

    Raw annotations, resources, mounts and diagnostics are discarded. Source
    IDs/timestamps remain private. No API history mutation, stream continuity,
    birth/bootstrap/tombstone fence or writer completion is established.
    """
    try:
        observed = _event_snapshot(event)
        if observed is None:
            return None
        snapshot, event_created = observed
        result = bind_cri_log_source(history, entry, node, snapshot, file_identity)
        if result is not None:
            result.update(metadata_observation='bundled_CRI_event',
                          event_type=event['containerEventType'], event_created=event_created)
        return result
    except Exception:
        raise ValueError('Private CRI event binding unavailable') from None


def _event_snapshot(event):
    """Normalize private bundled statuses; never synthesize deletion metadata."""
    try:
        if (not isinstance(event, dict)
                or len(json.dumps(event, allow_nan=False).encode()) > MAX_INPUT_BYTES
                or event.get('containerEventType') not in EVENT_TYPES):
            raise ValueError()
        identifier = _identifier(event.get('containerId'))
        event_created = _created(event.get('createdAt'))
        if event['containerEventType'] == 'CONTAINER_DELETED_EVENT':
            return None
        statuses, sandbox = event.get('containersStatuses'), event.get('podSandboxStatus')
        if (not isinstance(statuses, list) or len(statuses) > 128
                or not all(isinstance(value, dict) for value in statuses)
                or not isinstance(sandbox, dict)):
            raise ValueError()
        matching = [value for value in statuses if value.get('id') == identifier]
        if len(matching) != 1:
            raise ValueError()
        status, sandbox = copy.deepcopy((matching[0], sandbox))
        container_created = _inspected_created(status.get('createdAt'))
        sandbox_created = _inspected_created(sandbox.get('createdAt'))
        if event_created < container_created or event_created < sandbox_created:
            raise ValueError()
        sandbox_id = _identifier(sandbox.get('id'))
        container = copy.deepcopy(status)
        container.update(podSandboxId=sandbox_id, createdAt=str(container_created))
        sandbox_list = copy.deepcopy(sandbox)
        sandbox_list['createdAt'] = str(sandbox_created)
        # The association is explicitly the event's bundled PodSandboxStatus;
        # this adapter does not claim a separately observed inspect reply.
        snapshot = dict(container=container,
                        container_detail=dict(status=status, info=dict(sandboxID=sandbox_id)),
                        sandbox=sandbox_list, sandbox_detail=dict(status=sandbox))
        return snapshot, event_created
    except Exception:
        raise ValueError('Private CRI event binding unavailable') from None
