"""Private validated CRI metadata archive; missing births stay unresolved."""
import copy
import os
import threading
import time

from .cri_binding import bind_cri_log_source, _created
from .cri_staging import provisional_entry, _key
from .cri_runtime_event import _event_snapshot
from .evidence import positive
from .log_retention import _file_identity
from .pod_history import PodIdentityHistory


MAX_ENTRIES = 128
MAX_FILES = 512
MAX_OPERATIONS = 4096


class PrivateCRIRuntimeArchive:
    """Remember minimal attribution validated while runtime metadata exists.

    The original anchored history, Namespace binding, Node UID and node name
    remain fixed. capture receives independently authenticated CRI/Node snapshots
    and a held-file identity; bind_cri_log_source validates them before archival.
    check(reserve) verifies the original namespace/node/runtime/owner and both
    clocks. Per-call check(proof,reserve) independently verifies the observation
    and held file before and after admission or lookup. The proof is private.

    resolve requires no new runtime snapshot: immutable identity already observed
    survives runtime garbage collection. It rechecks original API history and
    exact file identity, refusing later API conflicts, CID reuse, changed creation
    times/sandbox association or file reuse across entries. Each generation needs
    its own independently verified capture; an unseen file never inherits a CID.
    Raw OCI/environment/annotations and state/diagnostics are never retained.

    Every summary says history_complete=False. Unknown fast-deleted containers
    remain unresolved; this is not a birth stream, tombstone, writer-close proof,
    bootstrap/API/time fence or owner-death recovery. Run in an owned bounded
    child for blocking guards. A refusal permanently discards archive metadata;
    callers must invalidate dependent collection. Copies released on close are
    not secure-erasure evidence. No archive metadata belongs in public receipts.
    """
    def __init__(self, history, *, node_uid, node_name, check, deadline):
        positive(deadline, 'Private CRI archive deadline')
        if type(history) is not PodIdentityHistory or not callable(check):
            raise ValueError('Private CRI archive inputs required')
        history._owned()
        _file_identity(dict(node_uid=node_uid, device=0, inode=1))
        # Use existing declaration-name validation without creating a source.
        provisional_entry(dict(namespace=history._binding['name'], pod_name=node_name,
            pod_uid='validation', container_name='validation', restart_index=0))
        self._history, self._binding = history, copy.deepcopy(history._binding)
        self._node, self._name, self._check, self._deadline = node_uid, node_name, check, deadline
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._records, self._entries, self._cids, self._sandboxes, self._files = {}, {}, {}, {}, {}
        self._operations = 0
        self._valid, self._closed = True, False
        try: self._verify()
        except BaseException as error:
            self._discard()
            if not isinstance(error, Exception): raise
            raise ValueError('Private CRI runtime archive unavailable') from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private CRI archive owner unavailable')

    def _verify(self):
        if (not self._valid or self._closed or time.monotonic()+5 >= self._deadline
                or self._check(5) is not True or not self._history.summary()['valid']
                or self._history._binding != self._binding):
            raise ValueError('Private CRI archive lifetime unavailable')

    def _operation(self):
        self._verify()
        if self._operations >= MAX_OPERATIONS:
            raise ValueError('Private CRI archive operation bound')
        self._operations += 1

    def _scope(self, entry, identity):
        entry = provisional_entry(entry)
        file_key = _file_identity(identity)
        if entry['namespace'] != self._binding['name'] or file_key[0] != self._node:
            raise ValueError('Private CRI archive scope unavailable')
        return entry, _key(entry), file_key

    def _declaration(self, entry, projection):
        value = self._history.runtime_declaration(entry)
        if (value is None or value['namespace_binding'] != self._binding
                or value['node_name'] != self._name or value['role'] != projection['role']):
            raise ValueError('Private CRI archive declaration unavailable')
        index, cid = entry['restart_index'], projection['source']['container_id']
        known = value['known_instances']
        if (index in known and known[index] != cid
                or any(prior != index and identifier == cid for prior, identifier in known.items())):
            raise ValueError('Private CRI archive API identity unavailable')
        result = copy.deepcopy(projection)
        result.update(pod_deleted=value['deleted'], api_pending=value['pending'],
                      api_container_id_observed=index in known)
        return result

    def _guarded(self, record, check):
        self._verify()
        if not callable(check) or check(copy.deepcopy(record), 5) is not True:
            raise ValueError('Private CRI archive observation unavailable')
        self._verify()

    def _discard(self):
        self._valid, self._closed = False, True
        self._records.clear(); self._entries.clear(); self._cids.clear()
        self._sandboxes.clear(); self._files.clear()

    def capture(self, entry, node, snapshot, file_identity, *, check):
        """Validate and remember one observed generation; return a private copy."""
        self._owned()
        with self._lock:
            try:
                self._operation()
                if not callable(check): raise ValueError('Private CRI archive check required')
                entry, node, snapshot, file_identity = copy.deepcopy((entry, node, snapshot, file_identity))
                entry, key, file_key = self._scope(entry, file_identity)
                projection = bind_cri_log_source(self._history, entry, node, snapshot, file_identity)
                if projection is None:
                    self._verify(); return None
                if (projection['namespace_binding'] != self._binding
                        or projection['node_uid'] != self._node or projection['node_name'] != self._name):
                    raise ValueError('Private CRI archive node unavailable')
                immutable = dict(container_id=projection['source']['container_id'],
                    container_created=_created(snapshot['container']['createdAt']),
                    sandbox_id=snapshot['sandbox']['id'],
                    sandbox_created=_created(snapshot['sandbox']['createdAt']), role=projection['role'])
                cid, sid = immutable['container_id'], immutable['sandbox_id']
                pod = (entry['namespace'], entry['pod_name'], entry['pod_uid'], immutable['sandbox_created'])
                if (key in self._entries and self._entries[key] != immutable
                        or cid in self._cids and self._cids[cid] != key
                        or sid in self._sandboxes and self._sandboxes[sid] != pod
                        or file_key in self._files and self._files[file_key] != key
                        or key not in self._entries and len(self._entries) >= MAX_ENTRIES
                        or file_key not in self._files and len(self._files) >= MAX_FILES):
                    raise ValueError('Private CRI archive identity or bound unavailable')
                record = dict(entry=entry, projection=projection, immutable=immutable)
                self._guarded(record, check)
                projection = self._declaration(entry, projection)
                record['projection'] = projection
                self._guarded(record, check)
                projection = self._declaration(entry, projection)
                record['projection'] = projection
                self._records[(key, file_key)] = copy.deepcopy(record)
                self._entries[key] = immutable; self._cids[cid] = key
                self._sandboxes[sid] = pod; self._files[file_key] = key
                return copy.deepcopy(projection)
            except BaseException as error:
                self._discard()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI runtime archive unavailable') from None

    def capture_event(self, entry, node, event, file_identity, *, check):
        """Archive one authenticated bundled event through the same file guards.

        The caller independently authenticates the event stream and original
        runtime/Node/Namespace/held file. No fresh list/inspect RPC is required.
        Metadata may have disappeared since the event was observed. Deletion
        yields None and never creates attribution; unknown births stay unresolved.
        The minimal stored record has the same identity/reuse/lifecycle rules as
        capture. Event bodies and diagnostics are not retained or made public.
        """
        self._owned()
        with self._lock:
            try:
                self._verify()
                if not callable(check):
                    raise ValueError('Private CRI archive check required')
                observed = _event_snapshot(copy.deepcopy(event))
                if observed is None:
                    self._operation()
                    self._verify()
                    return None
                snapshot, _ = observed
                return self.capture(entry, node, snapshot, file_identity, check=check)
            except BaseException as error:
                self._discard()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI runtime archive unavailable') from None

    def resolve(self, entry, file_identity, *, check):
        """Resolve only an already captured file, including after runtime GC."""
        self._owned()
        with self._lock:
            try:
                self._operation()
                if not callable(check): raise ValueError('Private CRI archive check required')
                entry, key, file_key = self._scope(entry, file_identity)
                record = self._records.get((key, file_key))
                if record is None:
                    self._verify(); return None
                record = copy.deepcopy(record)
                record['projection'] = self._declaration(entry, record['projection'])
                self._guarded(record, check)
                record['projection'] = self._declaration(entry, record['projection'])
                self._guarded(record, check)
                return self._declaration(entry, record['projection'])
            except BaseException as error:
                self._discard()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI runtime archive unavailable') from None

    def summary(self):
        self._owned()
        with self._lock:
            return dict(outcome='private_cri_runtime_archive', entries=len(self._entries),
                        files=len(self._files), operations=self._operations,
                        valid=self._valid and not self._closed,
                        metadata_released=self._closed, history_complete=False)

    def close(self):
        self._owned()
        with self._lock:
            self._discard()
            return self.summary()
