"""Event bodies must not fabricate file identity or resurrect deleted metadata."""
import copy
import unittest

from evaluation.cri_runtime_event import bind_cri_event_log_source
from test_evaluation_cri_binding import (CID, ENTRY, FILE, NODE, SECRET, SOURCE,
                                         pending_history, snapshots)


def runtime_event(kind='CONTAINER_CREATED_EVENT'):
    snapshot = snapshots()
    return dict(containerId=CID, containerEventType=kind,
                createdAt='1700000000000000003',
                podSandboxStatus=snapshot['sandbox_detail']['status'],
                containersStatuses=[snapshot['container_detail']['status']])


class RuntimeEventBindingTest(unittest.TestCase):
    def bind(self, value, **kwargs):
        return bind_cri_event_log_source(kwargs.get('history', pending_history()),
                                        kwargs.get('entry', ENTRY), NODE, value, FILE)

    def test_pending_birth_binds_without_mutating_api_or_retaining_raw_fields(self):
        h = pending_history()
        value = runtime_event()
        before = copy.deepcopy(value)
        result = self.bind(value, history=h)
        self.assertEqual(result['source'], SOURCE)
        self.assertEqual(result['metadata_observation'], 'bundled_CRI_event')
        self.assertEqual(result['event_created'], 1700000000000000003)
        self.assertFalse(result['history_complete'])
        self.assertFalse(result['api_container_id_observed'])
        self.assertEqual(h.sources(), [])
        self.assertEqual(value, before)
        self.assertNotIn(SECRET, repr(result))

    def test_live_types_require_exact_status_and_deletion_never_binds(self):
        for kind in ('CONTAINER_CREATED_EVENT', 'CONTAINER_STARTED_EVENT', 'CONTAINER_STOPPED_EVENT'):
            self.assertEqual(self.bind(runtime_event(kind))['source'], SOURCE)
        for statuses in ([], runtime_event()['containersStatuses']):
            value = runtime_event('CONTAINER_DELETED_EVENT')
            value['containersStatuses'] = statuses
            self.assertIsNone(self.bind(value))
        for statuses in ([], [runtime_event()['containersStatuses'][0]] * 2, [None]):
            value = runtime_event(); value['containersStatuses'] = statuses
            with self.assertRaises(ValueError): self.bind(value)

    def test_foreign_cid_scope_attempt_path_and_node_refuse(self):
        for mode in ('cid', 'uid', 'path', 'attempt', 'sandbox', 'node'):
            value = runtime_event(); status = value['containersStatuses'][0]
            if mode == 'cid': value['containerId'] = 'c' * 64
            elif mode == 'uid': status['labels']['io.kubernetes.pod.uid'] = 'foreign'
            elif mode == 'path': status['logPath'] = '/foreign/0.log'
            elif mode == 'attempt': status['metadata']['attempt'] = True
            elif mode == 'sandbox': value['podSandboxStatus']['metadata']['name'] = 'foreign'
            else:
                node = copy.deepcopy(NODE); node['metadata']['uid'] = 'foreign'
                with self.assertRaises(ValueError):
                    bind_cri_event_log_source(pending_history(), ENTRY, node, value, FILE)
                continue
            with self.assertRaises(ValueError): self.bind(value)

    def test_event_timestamp_and_shape_are_bounded_without_coercion(self):
        for timestamp in (True, 1700000000000000003, '0', str(2**63), '1700000000000000000'):
            value = runtime_event(); value['createdAt'] = timestamp
            with self.assertRaises(ValueError): self.bind(value)
        for kind in ('unknown', None, 1):
            value = runtime_event(); value['containerEventType'] = kind
            with self.assertRaises(ValueError): self.bind(value)
        value = runtime_event(); value['private'] = 'x' * (2 * 1024 * 1024)
        with self.assertRaises(ValueError): self.bind(value)
        value = runtime_event(); value['containersStatuses'] *= 129
        with self.assertRaises(ValueError): self.bind(value)

    def test_rfc3339_status_timestamps_and_unknown_declaration(self):
        value = runtime_event()
        value['containersStatuses'][0]['createdAt'] = '2023-11-14T22:13:20.000000001Z'
        value['podSandboxStatus']['createdAt'] = '2023-11-14T22:13:20Z'
        self.assertEqual(self.bind(value)['source'], SOURCE)
        self.assertIsNone(self.bind(value, entry=dict(ENTRY, container_name='unknown')))

    def test_refusal_does_not_echo_raw_event_or_diagnostics(self):
        value = runtime_event(); value['containerId'] = SECRET
        with self.assertRaisesRegex(ValueError, '^Private CRI event binding unavailable$') as failure:
            self.bind(value)
        self.assertNotIn(SECRET, str(failure.exception))
