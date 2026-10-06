"""Private current/previous Kubernetes source discovery, not history attestation.

The operator supplies a namespace identity and complete unfiltered PodList from a
trusted independently bound API client. Snapshots cannot prove absence of deleted
Pods, rotated logs or transient containers between observations.
"""
import hashlib
import json
import re

from .log_transport import source_binding


MAX_SOURCES = 128


def available_log_inventory(namespace, pods, *, binding):
    """Return private source bindings and a stable identity/count fingerprint.

    All regular, init (including restartable sidecars) and ephemeral containers
    are inspected. Missing/ambiguous identities or pagination are unavailable,
    never omitted silently. More than one restart marks restart_history_gap;
    even False is not proof of whole namespace/log history. No raw Pod fields or
    exception text should be persisted by the caller. Namespace/list collection,
    API identity, selector absence, time bounds and continuity remain caller-owned.
    """
    def unavailable():
        raise ValueError('Complete independently bound log inventory unavailable')

    if (not isinstance(binding, dict) or set(binding) != {'name', 'uid'}
            or not isinstance(binding['name'], str)
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', binding['name'])
            or not isinstance(binding['uid'], str) or not binding['uid']
            or '\x00' in binding['uid'] or len(binding['uid'].encode()) > 512):
        unavailable()
    if not isinstance(namespace, dict) or namespace.get('kind') != 'Namespace' or namespace.get('apiVersion') != 'v1':
        unavailable()
    metadata = namespace.get('metadata')
    if (not isinstance(metadata, dict) or metadata.get('name') != binding['name']
            or metadata.get('uid') != binding['uid'] or metadata.get('deletionTimestamp')):
        unavailable()
    if not isinstance(pods, dict) or pods.get('kind') != 'PodList' or pods.get('apiVersion') != 'v1':
        unavailable()
    metadata = pods.get('metadata')
    if (not isinstance(metadata, dict) or metadata.get('continue')
            or metadata.get('remainingItemCount') not in (None, 0)
            or type(metadata.get('remainingItemCount')) is bool):
        unavailable()
    version = metadata.get('resourceVersion')
    if not isinstance(version, str) or not version or '\x00' in version or len(version.encode()) > 512:
        unavailable()
    items = pods.get('items')
    if not isinstance(items, list) or len(items) > MAX_SOURCES:
        unavailable()
    sources, catalog, names, uids = [], [], set(), set()
    history_unavailable = False
    for pod in items:
        if not isinstance(pod, dict): unavailable()
        metadata, spec, status = (pod.get(key) for key in ('metadata', 'spec', 'status'))
        if not all(isinstance(value, dict) for value in (metadata, spec, status)): unavailable()
        name, uid = metadata.get('name'), metadata.get('uid')
        if (metadata.get('namespace') != binding['name'] or not isinstance(name, str)
                or not isinstance(uid, str) or name in names or uid in uids):
            unavailable()
        # Validate identities even for a Pod with no available container logs.
        source_binding(dict(namespace=binding['name'], pod_name=name, pod_uid=uid,
                            container_name='validation', container_id='validation', previous=False))
        names.add(name); uids.add(uid)
        containers, pod_names = [], set()
        for declarations, observations in (('containers', 'containerStatuses'),
                                           ('initContainers', 'initContainerStatuses'),
                                           ('ephemeralContainers', 'ephemeralContainerStatuses')):
            declared, observed = spec.get(declarations, []), status.get(observations, [])
            if (not isinstance(declared, list) or not isinstance(observed, list)
                    or len(declared) > 32 or len(observed) != len(declared)):
                unavailable()
            expected = []
            for container in declared:
                container_name = container.get('name') if isinstance(container, dict) else None
                if (not isinstance(container_name, str) or not re.fullmatch(
                        r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', container_name)
                        or container_name in pod_names): unavailable()
                pod_names.add(container_name); expected.append(container_name)
            actual = {}
            for container in observed:
                if not isinstance(container, dict) or not isinstance(container.get('name'), str): unavailable()
                if container['name'] in actual: unavailable()
                actual[container['name']] = container
            if set(actual) != set(expected): unavailable()
            for container_name in expected:
                container = actual[container_name]
                count, state = container.get('restartCount'), container.get('state')
                if (type(count) is not int or not 0 <= count <= 1000000
                        or not isinstance(state, dict) or len(state) != 1
                        or next(iter(state)) not in ('running', 'terminated', 'waiting')
                        or not isinstance(next(iter(state.values())), dict)):
                    unavailable()
                current = container.get('containerID')
                previous = container.get('lastState', {})
                if not isinstance(previous, dict): unavailable()
                if 'waiting' in state:
                    # A never-started container has no logs. Waiting after a
                    # restart can carry a stale current ID; do not alias it.
                    if count != 0 or current or previous: unavailable()
                    containers.append((declarations, container_name, count, None, None))
                    continue
                source = dict(namespace=binding['name'], pod_name=name, pod_uid=uid,
                              container_name=container_name, container_id=current, previous=False)
                sources.append(source_binding(source))
                prior_id = None
                if count:
                    if set(previous) != {'terminated'}: unavailable()
                    terminated = previous.get('terminated')
                    if not isinstance(terminated, dict): unavailable()
                    prior_id = terminated.get('containerID')
                    if prior_id == current: unavailable()
                    sources.append(source_binding(dict(source, container_id=prior_id, previous=True)))
                elif previous:
                    unavailable()
                history_unavailable |= count > 1
                containers.append((declarations, container_name, count, current, prior_id))
        if not spec.get('containers'): unavailable()
        catalog.append((name, uid, bool(metadata.get('deletionTimestamp')), sorted(containers)))
        if len(sources) > MAX_SOURCES: unavailable()
    fingerprint = hashlib.sha256(json.dumps(dict(namespace=binding, pods=sorted(catalog)),
                                           sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    sources.sort(key=lambda value: (value['pod_name'], value['container_name'], value['previous']))
    return dict(sources=sources, fingerprint=fingerprint, resource_version=version,
                restart_history_gap=history_unavailable)
