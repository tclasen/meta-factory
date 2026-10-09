"""Private anchored Pod/container identity history, not log coverage evidence."""
import copy
import json
import os
import threading

from .log_transport import source_binding
from .cri_staging import provisional_entry
from .pod_watch import MAX_EVENT_BYTES, _version, watch_event
from .watch_cursor import PodWatchCursor


MAX_PODS = 128
MAX_CONTAINERS = 128
MAX_IDENTITIES = 128
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
_ROLES = (('containers', 'containerStatuses'), ('initContainers', 'initContainerStatuses'),
          ('ephemeralContainers', 'ephemeralContainerStatuses'))


class PodIdentityHistory:
    """Keep all observed immutable identities, including deleted Pods/restarts.

    Construct from an independently verified Namespace and complete unfiltered
    PodList. begin/accept/finish wrap the exact trusted PodWatchTransport window
    protocol. Pending/missing statuses never silently omit declared containers.
    Unknown events, identity/count regressions and failed windows permanently
    invalidate this history; never relist/rebaseline. Raw Pod fields, annotations,
    environment, error text and versions do not appear in public summaries.

    sources() is private trusted collector input, not an acceptance receipt.
    Available selectors describe the latest observation; older/deleted sources
    require independent node/file binding. This tracks identities, not collected
    bytes, bootstrap/rotation completeness, API/time fences or owner-death proof.
    Every summary says history_complete=False.
    """
    def __init__(self, namespace, pods, *, binding):
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._valid, self._events, self._gap = True, 0, False
        self._pods, self._active = {}, {}
        self._binding = copy.deepcopy(binding)
        self._cursor = None
        try:
            if (not isinstance(binding, dict) or set(binding) != {'name', 'uid'}
                    or not isinstance(namespace, dict) or namespace.get('kind') != 'Namespace'
                    or namespace.get('apiVersion') != 'v1'):
                self._refuse()
            metadata = namespace.get('metadata')
            if (not isinstance(metadata, dict) or metadata.get('name') != binding['name']
                    or metadata.get('uid') != binding['uid'] or metadata.get('deletionTimestamp')):
                self._refuse()
            if not isinstance(pods, dict) or pods.get('kind') != 'PodList' or pods.get('apiVersion') != 'v1':
                self._refuse()
            if len(json.dumps(pods, allow_nan=False, ensure_ascii=False).encode()) > MAX_SNAPSHOT_BYTES:
                self._refuse()
            metadata = pods.get('metadata')
            if (not isinstance(metadata, dict) or metadata.get('continue')
                    or metadata.get('remainingItemCount') is not None and
                    (type(metadata['remainingItemCount']) is not int or metadata['remainingItemCount'] != 0)):
                self._refuse()
            self._cursor = PodWatchCursor(binding, _version(metadata.get('resourceVersion')))
            items = pods.get('items')
            if not isinstance(items, list) or len(items) > MAX_PODS: self._refuse()
            for value in items:
                if not isinstance(value, dict): self._refuse()
                # Kubernetes omits item TypeMeta in a typed PodList. Only this
                # verified list context supplies missing fields; explicit wrong
                # types and watch events still fail normal Pod validation.
                value = dict(value)
                value.setdefault('apiVersion', 'v1')
                value.setdefault('kind', 'Pod')
                state = self._pod(value)
                if state['uid'] in self._pods or state['name'] in self._active: self._refuse()
                self._install(state)
        except Exception: self._refuse()

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private Pod history owner unavailable')

    def _refuse(self):
        self._valid = False
        if self._cursor is not None: self._cursor.abandon()
        raise ValueError('Private Pod identity history unavailable') from None

    def _pod(self, value, previous=None):
        raw = json.dumps(dict(type='ADDED', object=value), allow_nan=False, ensure_ascii=False).encode()
        if len(raw) > MAX_EVENT_BYTES: self._refuse()
        obj = watch_event(raw, self._binding['name'])['object']
        metadata, spec, status = obj['metadata'], obj.get('spec'), obj.get('status', {})
        if metadata['resourceVersion'] == '0' or not isinstance(spec, dict) or not isinstance(status, dict):
            self._refuse()
        uid, name = metadata['uid'], metadata['name']
        node = spec.get('nodeName', '')
        if not isinstance(node, str): self._refuse()
        if node:
            source_binding(dict(namespace=self._binding['name'], pod_name=node, pod_uid='validation',
                                container_name='validation', container_id='validation', previous=False))
        if previous is not None and (uid != previous['uid'] or name != previous['name']
                                      or previous['node'] and node != previous['node']):
            self._refuse()
        containers = {}
        for role, observations in _ROLES:
            declarations, observed = spec.get(role, []), status.get(observations, [])
            if (not isinstance(declarations, list) or len(declarations) > 32
                    or not isinstance(observed, list) or len(observed) > len(declarations)):
                self._refuse()
            for declaration in declarations:
                container = declaration.get('name') if isinstance(declaration, dict) else None
                source_binding(dict(namespace=self._binding['name'], pod_name=name, pod_uid=uid,
                                    container_name=container, container_id='validation', previous=False))
                if container in containers: self._refuse()
                old = previous['containers'].get(container) if previous is not None else None
                if old is not None and old['role'] != role: self._refuse()
                state = copy.deepcopy(old) if old is not None else dict(role=role, count=None, ids={})
                state.update(pending=True, current=None, previous=None)
                containers[container] = state
            names = set()
            for observation in observed:
                if not isinstance(observation, dict): self._refuse()
                container = observation.get('name')
                if container in names or container not in containers or containers[container]['role'] != role:
                    self._refuse()
                names.add(container)
                state = containers[container]
                count, current_state = observation.get('restartCount'), observation.get('state')
                if (type(count) is not int or not 0 <= count <= 1000000
                        or state['count'] is not None and count < state['count']
                        or not isinstance(current_state, dict) or len(current_state) != 1
                        or next(iter(current_state)) not in ('waiting', 'running', 'terminated')
                        or not isinstance(next(iter(current_state.values())), dict)):
                    self._refuse()
                state['count'] = count
                last = observation.get('lastState', {})
                if not isinstance(last, dict) or last and (set(last) != {'terminated'} or not isinstance(last['terminated'], dict)):
                    self._refuse()
                prior = last.get('terminated', {}).get('containerID')
                if prior:
                    if not node: self._refuse()
                    # Kubelet can move the latest terminated attempt into
                    # lastState while waiting, without advancing restartCount.
                    # Preserve that index only if its identity was already seen;
                    # a cached older ID cannot manufacture a new instance.
                    if 'waiting' in current_state and state['ids'].get(count) == prior:
                        prior_index = count
                    else:
                        if not count: self._refuse()
                        prior_index = count-1
                    self._identity(state, prior_index, prior, name, uid)
                    state['previous'] = prior_index
                elif prior is not None and prior != '': self._refuse()
                current = observation.get('containerID')
                if current is not None and current != '':
                    source_binding(dict(namespace=self._binding['name'], pod_name=name, pod_uid=uid,
                                        container_name=container, container_id=current, previous=False))
                terminated = current_state.get('terminated', {}).get('containerID')
                if terminated is not None and terminated != '':
                    source_binding(dict(namespace=self._binding['name'], pod_name=name, pod_uid=uid,
                                        container_name=container, container_id=terminated, previous=False))
                    if current and terminated != current: self._refuse()
                    current = terminated
                if 'waiting' not in current_state and current:
                    if not node: self._refuse()
                    self._identity(state, count, current, name, uid)
                    state.update(pending=False, current=count)
                elif current is not None and not isinstance(current, str): self._refuse()
        if not spec.get('containers'): self._refuse()
        if previous is not None:
            for role, _ in _ROLES:
                old = {key for key, value in previous['containers'].items() if value['role'] == role}
                new = {key for key, value in containers.items() if value['role'] == role}
                if old != new and (role != 'ephemeralContainers' or not old <= new): self._refuse()
        return dict(uid=uid, name=name, node=node, containers=containers, deleted=False)

    def _identity(self, state, index, identity, name, uid):
        source_binding(dict(namespace=self._binding['name'], pod_name=name, pod_uid=uid,
                            container_name='validation', container_id=identity, previous=False))
        if (index in state['ids'] and state['ids'][index] != identity
                or any(value == identity and key != index for key, value in state['ids'].items())):
            self._refuse()
        state['ids'][index] = identity

    def _install(self, state):
        candidate = dict(self._pods)
        candidate[state['uid']] = state
        containers = [value for pod in candidate.values() for value in pod['containers'].values()]
        if (len(candidate) > MAX_PODS or len(containers) > MAX_CONTAINERS
                or sum(len(value['ids']) for value in containers) > MAX_IDENTITIES):
            self._refuse()
        for value in state['containers'].values():
            required = value['count'] + (value['current'] is not None) if value['count'] is not None else 0
            if len(value['ids']) < required: self._gap = True
        self._pods = candidate
        if state['deleted']: self._active.pop(state['name'], None)
        else: self._active[state['name']] = state['uid']

    def begin(self):
        self._owned()
        with self._lock:
            if not self._valid: self._refuse()
            try: return self._cursor.begin()
            except Exception: self._refuse()

    def accept(self, event):
        self._owned()
        with self._lock:
            try:
                if not self._valid: self._refuse()
                raw = json.dumps(event, allow_nan=False, ensure_ascii=False).encode()
                if len(raw) > MAX_EVENT_BYTES: self._refuse()
                value = watch_event(raw, self._binding['name'])
                state = None
                if value['type'] != 'BOOKMARK':
                    uid, name = (value['object']['metadata'][key] for key in ('uid', 'name'))
                    previous = self._pods.get(uid)
                    if value['type'] == 'ADDED':
                        if previous is not None or name in self._active: self._refuse()
                    elif previous is None or previous['deleted'] or self._active.get(name) != uid:
                        self._refuse()
                    state = self._pod(value['object'], previous)
                    state['deleted'] = value['type'] == 'DELETED'
                self._cursor.accept(value)
                if state is not None: self._install(state)
                self._events += 1
            except Exception: self._refuse()

    def finish(self, receipt):
        self._owned()
        with self._lock:
            if not self._valid: self._refuse()
            try:
                self._cursor.finish(receipt)
                return self.summary()
            except Exception: self._refuse()

    def sources(self):
        """Private copied source/index/node/availability inputs; never evidence."""
        self._owned()
        with self._lock:
            if not self._valid: self._refuse()
            result = []
            for pod in self._pods.values():
                for name, value in pod['containers'].items():
                    for index, identity in value['ids'].items():
                        availability = ('historical' if pod['deleted'] else
                                        'current' if value['current'] == index else
                                        'previous' if value['previous'] == index else 'historical')
                        result.append(dict(source=dict(namespace=self._binding['name'], pod_name=pod['name'],
                            pod_uid=pod['uid'], container_name=name, container_id=identity, previous=availability=='previous'),
                            restart_index=index, role=value['role'], node_name=pod['node'], available_as=availability))
            return copy.deepcopy(result)

    def runtime_declaration(self, entry):
        """Private minimal anchored declaration, including absent API statuses.

        None means this Pod/container was not declared in this Namespace history;
        filesystem/runtime names cannot manufacture an API association. The
        caller must independently bind node UID, runtime metadata and file IDs.
        This projection does not register runtime CIDs or resolve coverage gaps.
        """
        self._owned()
        with self._lock:
            if not self._valid: self._refuse()
            try: entry = provisional_entry(entry)
            except Exception:
                raise ValueError('Private runtime declaration input unavailable') from None
            pod = self._pods.get(entry['pod_uid'])
            if (entry['namespace'] != self._binding['name'] or pod is None
                    or pod['name'] != entry['pod_name']):
                return None
            container = pod['containers'].get(entry['container_name'])
            if container is None: return None
            return copy.deepcopy(dict(namespace_binding=self._binding, node_name=pod['node'],
                role=container['role'], deleted=pod['deleted'], pending=container['pending'],
                observed_restart_count=container['count'], known_instances=container['ids']))

    def summary(self):
        self._owned()
        with self._lock:
            return dict(valid=self._valid, history_complete=False, observed_events=self._events,
                        pods_seen=len(self._pods), active_pods=len(self._active),
                        deleted_pods=sum(value['deleted'] for value in self._pods.values()),
                        identities=sum(len(value['ids']) for pod in self._pods.values() for value in pod['containers'].values()),
                        pending_containers=sum(value['pending'] for pod in self._pods.values() if not pod['deleted'] for value in pod['containers'].values()),
                        unresolved_deleted_containers=sum(value['pending'] for pod in self._pods.values() if pod['deleted'] for value in pod['containers'].values()),
                        identity_gap=self._gap)

    def abandon(self):
        self._owned()
        with self._lock:
            self._valid = False
            self._cursor.abandon()
