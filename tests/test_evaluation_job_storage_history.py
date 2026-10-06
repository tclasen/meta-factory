"""Physical overwritten/deleted artifacts remain visible in guarded history."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.job_broker import JobObservationError
from evaluation.job_storage import S3ArtifactHistory, S3VersionListTransport


IDENTITY = '00000000-0000-0000-0000-000000000001'
PREFIX = 'exports/'+IDENTITY+'/'


def version(key='artifact.zip', identity='v1', latest=True):
    return dict(Key=PREFIX+key, VersionId=identity, IsLatest=latest)


def page(versions=(), deletions=(), marker=None, next_marker=None):
    value = dict(Name='fixture-bucket', Prefix=PREFIX, IsTruncated=next_marker is not None,
                 Versions=list(versions), DeleteMarkers=list(deletions))
    if marker:
        value.update(KeyMarker=marker[0], VersionIdMarker=marker[1])
    if next_marker:
        value.update(NextKeyMarker=next_marker[0], NextVersionIdMarker=next_marker[1])
    return value


class ArtifactHistoryTest(unittest.TestCase):
    def history(self, pages, **overrides):
        self.calls = []
        def transport(bucket, prefix, marker, *, timeout):
            self.calls.append((bucket, prefix, marker, timeout))
            return pages.pop(0)
        arguments = dict(check=lambda reserve: None)
        arguments.update(overrides)
        return S3ArtifactHistory(transport, 'fixture-bucket', lambda identity: PREFIX, **arguments)

    def test_same_key_overwrites_and_deleted_artifact_count_separately(self):
        marker = (PREFIX+'artifact.zip', 'v2')
        history = self.history([
            page([version(identity='v3'), version(identity='v2', latest=False)], next_marker=marker),
            page([version(identity='v1', latest=False), version('deleted.zip', 'v1', False)],
                 [version('deleted.zip', 'delete1')], marker=marker)])
        self.assertEqual(history(IDENTITY, timeout=15), dict(versions=4, delete_markers=1,
            keys=2, current_objects=1, current_delete_markers=1, history_complete=False))
        self.assertEqual([v[2] for v in self.calls], [None, marker])
        self.assertTrue(all(0 < v[3] <= 15 for v in self.calls))

    def test_empty_and_unversioned_null_history(self):
        self.assertEqual(self.history([page()])(IDENTITY, timeout=15)['versions'], 0)
        result = self.history([page([version(identity='null')])])(IDENTITY, timeout=15)
        self.assertEqual(result['versions'], 1)
        self.assertEqual(result['current_objects'], 1)

    def test_empty_final_marker_is_equivalent_to_absent_continuation(self):
        value = page([version()])
        value.update(NextVersionIdMarker='', NextKeyMarker='')
        result = self.history([value])(IDENTITY, timeout=15)
        self.assertEqual(result['versions'], 1)
        value['NextVersionIdMarker'] = 'unexpected-private-version'
        with self.assertRaises(JobObservationError):
            self.history([value])(IDENTITY, timeout=15)

    def test_hostile_scope_shapes_and_identity_are_refused(self):
        changes = [dict(Name='other'), dict(Prefix='other/'), dict(IsTruncated=1),
                   dict(KeyMarker='unexpected'), dict(VersionIdMarker='unexpected'),
                   dict(CommonPrefixes=[{'Prefix': PREFIX}]), dict(Versions={}),
                   dict(DeleteMarkers={}), dict(Versions=[{}]),
                   dict(Versions=[dict(version(), IsLatest=1)]),
                   dict(Versions=[dict(version(), Key='outside')]),
                   dict(Versions=[dict(version(), VersionId='')]),
                   dict(Versions=[dict(version(), VersionId='private\x00secret')]),
                   dict(Versions=[version()]*1001)]
        for change in changes:
            with self.subTest(change=change):
                value = page([version()])
                value.update(change)
                with self.assertRaises(JobObservationError):
                    self.history([value])(IDENTITY, timeout=15)

    def test_duplicate_versions_latest_and_missing_latest_are_refused(self):
        variants = [page([version(), version()]), page([version(), version(identity='v2')]),
                    page([version()], [version()]), page([version(latest=False)])]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(JobObservationError):
                self.history([value])(IDENTITY, timeout=15)

    def test_repeated_marker_wrong_echo_and_outside_scope_refused(self):
        marker = (PREFIX+'artifact.zip', 'v1')
        first = page([version()], next_marker=marker)
        cases = [[first, page([version(identity='v2', latest=False)], next_marker=marker, marker=marker)],
                 [first, page([version(identity='v2', latest=False)])],
                 [page([version()], next_marker=('outside', 'v1'))],
                 [dict(page([version()]), NextKeyMarker=PREFIX+'artifact.zip')]]
        for pages in cases:
            with self.subTest(pages=pages), self.assertRaises(JobObservationError):
                self.history(copy.deepcopy(pages))(IDENTITY, timeout=15)

    def test_opaque_scoped_key_marker_is_forwarded_without_parsing(self):
        marker = (PREFIX+'artifact.zip[minio_cache:v2,id:private-cache]', 'v1')
        history = self.history([page([version()], next_marker=marker),
            page([version(identity='older', latest=False)], marker=marker)])
        self.assertEqual(history(IDENTITY, timeout=15)['versions'], 2)
        self.assertEqual(self.calls[1][2], marker)

    def test_page_bound_and_guard_revocation_are_inconclusive(self):
        marker = (PREFIX+'artifact.zip', 'v1')
        with self.assertRaises(JobObservationError):
            self.history([page([version()], next_marker=marker)], max_pages=1)(IDENTITY, timeout=15)
        checks = iter([None, RuntimeError('private-guard-secret')])
        def check(reserve):
            result = next(checks)
            if result:
                raise result
        with self.assertRaises(RuntimeError):
            self.history([page([version()])], check=check)(IDENTITY, timeout=15)

    def test_elapsed_deadline_suppresses_complete_page(self):
        now = [0]
        def transport(*args, **kwargs):
            now[0] = 16
            return page([version()])
        history = S3ArtifactHistory(transport, 'fixture-bucket', lambda identity: PREFIX,
            check=lambda reserve: None, monotonic=lambda: now[0])
        with self.assertRaises(JobObservationError):
            history(IDENTITY, timeout=15)


class VersionTransportTest(unittest.TestCase):
    def test_actual_child_uses_version_markers_and_never_logs_private_body(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            client = root/'client.py'
            client.write_text('''import json,sys
assert sys.argv[1:3]==['s3api','list-object-versions']
assert sys.argv[sys.argv.index('--key-marker')+1]==sys.argv[sys.argv.index('--prefix')+1]+'private-key'
assert sys.argv[sys.argv.index('--version-id-marker')+1]=='private-version'
assert '--no-paginate' in sys.argv and '--continuation-token' not in sys.argv
assert sys.argv[sys.argv.index('--max-keys')+1]=='2'
print(json.dumps({'private-body':'private-key'}))
print('private-stderr',file=sys.stderr)
''')
            with Attempt(root/'logs', {}) as attempt:
                transport = S3VersionListTransport(attempt, [sys.executable, str(client)],
                                                  check=lambda reserve: None, cwd=root, page_size=2)
                result = transport('fixture-bucket', PREFIX,
                                   (PREFIX+'private-key', 'private-version'), timeout=2)
                self.assertEqual(result, {'private-body': 'private-key'})
                for marker in [('outside', 'v1'), (PREFIX+'key', ''), (PREFIX+'key', 'v1', 'extra')]:
                    with self.assertRaises(ValueError):
                        transport('fixture-bucket', PREFIX, marker, timeout=2)
                for size in [True, 0, 1001]:
                    with self.assertRaises(ValueError):
                        S3VersionListTransport(attempt, [sys.executable, str(client)],
                                              check=lambda reserve: None, cwd=root, page_size=size)
            for path in (root/'logs').rglob('*'):
                if path.is_file():
                    for secret in ['private-key', 'private-version', 'private-body', 'private-stderr', IDENTITY]:
                        self.assertNotIn(secret, path.read_text())
