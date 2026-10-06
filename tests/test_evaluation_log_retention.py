"""Late canaries survive rotation/deletion without inventing history coverage."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.log_retention import PrivateCRIRetention


BINDING = dict(name='incident-app', uid='namespace-uid')
SOURCE = dict(namespace='incident-app', pod_name='api', pod_uid='pod-uid',
              container_name='runtime', container_id='containerd://one', previous=False)
FIRST = dict(node_uid='node-uid', device=1, inode=10)
SECOND = dict(FIRST, inode=11)
CANARY = b'private\x00\xff-archive\nsecond-line'


def frame(value, stream=b'stdout', tag=b'F'):
    return b'2026-10-05T12:30:45.123456789Z '+stream+b' '+tag+b' '+value+b'\n'


class LogRetentionTest(unittest.TestCase):
    def test_growing_partial_fragments_cross_rotation_and_private_late_inspection(self):
        retention = PrivateCRIRetention(BINDING)
        retention.open(SOURCE, FIRST)
        raw = frame(CANARY.split(b'\n')[0][:9], tag=b'P')
        retention.append(SOURCE, FIRST, 0, raw[:7])
        retention.append(SOURCE, FIRST, 7, raw[7:])
        retention.rotate(SOURCE, FIRST, SECOND, final_size=len(raw))
        end = frame(b'unrelated', b'stderr')+frame(CANARY.split(b'\n')[0][9:])+frame(CANARY.split(b'\n')[1])
        retention.append(dict(SOURCE, previous=True), SECOND, 0, end)
        retention.seal(SOURCE, SECOND, final_size=len(end))
        receipt = retention.inspect(binary_values=[CANARY])
        self.assertTrue(receipt['canary_present'])
        self.assertTrue(receipt['retention_valid'])
        self.assertFalse(receipt['history_complete'])
        self.assertEqual((receipt['sources'], receipt['decoded_sources'], receipt['files']), (1, 1, 2))
        self.assertNotIn(CANARY.hex(), repr(receipt))
        self.assertNotIn('containerd://one', repr(receipt))

    def test_real_file_rename_growth_and_unlink_do_not_erase_private_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'0.log'
            first = frame(b'ordinary')
            path.write_bytes(first)
            stat = path.stat();identity = dict(node_uid='node-uid',device=stat.st_dev,inode=stat.st_ino)
            retention = PrivateCRIRetention(BINDING);retention.open(SOURCE, identity)
            retention.append(SOURCE, identity, 0, path.read_bytes())
            old = path.with_name('0.log.1');path.rename(old)
            path.write_bytes(frame(b'private-rotation-canary'))
            stat = path.stat();new = dict(node_uid='node-uid',device=stat.st_dev,inode=stat.st_ino)
            retention.rotate(SOURCE, identity, new, final_size=old.stat().st_size)
            retention.append(SOURCE, new, 0, path.read_bytes())
            old.unlink();path.unlink()
            self.assertTrue(retention.inspect(['private-rotation-canary'])['canary_present'])

    def test_unrelated_containers_and_streams_never_join(self):
        for separate in ('stream', 'container'):
            retention = PrivateCRIRetention(BINDING);retention.open(SOURCE, FIRST)
            retention.append(SOURCE, FIRST, 0, frame(b'private-', tag=b'P'))
            if separate == 'stream':
                retention.append(SOURCE, FIRST, len(frame(b'private-', tag=b'P')), frame(b'canary', b'stderr'))
            else:
                other = dict(SOURCE, container_id='containerd://two')
                retention.open(other, SECOND);retention.append(other, SECOND, 0, frame(b'canary'))
            self.assertFalse(retention.inspect(['private-canary'])['canary_present'])

    def test_gap_overlap_source_mismatch_and_late_write_permanently_invalidate(self):
        raw = frame(b'private-gap-canary')
        for action in ('gap', 'overlap', 'source', 'late', 'size', 'inode', 'node', 'device', 'frame'):
            retention = PrivateCRIRetention(BINDING);retention.open(SOURCE, FIRST)
            retention.append(SOURCE, FIRST, 0, raw)
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, '^Private log retention unavailable$'):
                if action in ('gap','overlap'): retention.append(SOURCE, FIRST, len(raw)+(1 if action=='gap' else -1), b'next')
                elif action=='source': retention.append(dict(SOURCE, pod_uid='other'), FIRST, len(raw), b'next')
                elif action=='late':
                    retention.seal(SOURCE, FIRST, final_size=len(raw));retention.append(SOURCE, FIRST, len(raw), b'next')
                elif action=='size': retention.rotate(SOURCE, FIRST, SECOND, final_size=len(raw)+1)
                elif action in ('inode','node','device'):
                    new = FIRST if action=='inode' else dict(SECOND, **({'node_uid':'other'} if action=='node' else {'device':2}))
                    retention.rotate(SOURCE, FIRST, new, final_size=len(raw))
                else:
                    retention.append(SOURCE, FIRST, len(raw), b'incomplete frame');retention.seal(SOURCE, FIRST, final_size=len(raw)+16)
            self.assertFalse(retention.inspect(['private-gap-canary'])['retention_valid'])
            with self.assertRaises(ValueError): retention.append(SOURCE, FIRST, len(raw), b'')

    def test_old_positive_survives_failed_collection_or_malformed_later_file(self):
        raw = frame(b'private-retained-canary')
        for failure in ('abandon', 'bound', 'malformed', 'tail'):
            retention = PrivateCRIRetention(BINDING,max_bytes=len(raw)+1)
            retention.open(SOURCE, FIRST);retention.append(SOURCE, FIRST, 0, raw)
            if failure=='abandon': retention.abandon()
            elif failure=='bound':
                with self.assertRaises(ValueError): retention.append(SOURCE, FIRST, len(raw), b'xx')
            elif failure=='malformed':
                retention.rotate(SOURCE, FIRST, SECOND, final_size=len(raw));retention.append(SOURCE, SECOND, 0, b'x')
            else:
                retention.append(SOURCE, FIRST, len(raw), b'x')
            receipt = retention.inspect(['private-retained-canary'])
            self.assertTrue(receipt['canary_present'])
            self.assertFalse(receipt['history_complete'])
            if failure in ('malformed','tail'): self.assertEqual(receipt['decoded_sources'], 0)

    def test_namespace_binding_and_file_inputs_are_copied(self):
        binding, source, identity = dict(BINDING), dict(SOURCE), dict(FIRST)
        retention = PrivateCRIRetention(binding);retention.open(source, identity)
        binding['name']='other';source['pod_uid']='other';identity['inode']=999
        retention.append(SOURCE, FIRST, 0, frame(b'ordinary'))
        self.assertTrue(retention.inspect(['absent-canary'])['retention_valid'])

    def test_bounds_invalid_requests_and_original_parent_ownership(self):
        for value in (True, 0, 64*1024*1024+1):
            with self.assertRaises(ValueError): PrivateCRIRetention(BINDING,max_bytes=value)
        for name in ('MAX_SOURCES','MAX_FILES','MAX_OPERATIONS'):
            retention = PrivateCRIRetention(BINDING)
            with patch('evaluation.log_retention.'+name, 0), self.assertRaises(ValueError):retention.open(SOURCE,FIRST)
            self.assertFalse(retention.inspect(['absent-canary'])['retention_valid'])
        for identity in (dict(FIRST,inode=True),dict(FIRST,device=-1),dict(FIRST,node_uid=''),dict(FIRST,extra='private')):
            retention = PrivateCRIRetention(BINDING)
            with self.assertRaises(ValueError):retention.open(SOURCE,identity)
        retention = PrivateCRIRetention(BINDING)
        with patch('evaluation.log_retention.os.getpid',return_value=-1), self.assertRaises(ValueError):retention.open(SOURCE,FIRST)
        with self.assertRaises(ValueError):retention.inspect(['short'])
        retention.open(SOURCE,FIRST)
        self.assertTrue(retention.inspect(['absent-canary'])['retention_valid'])
        retention.close()
        with self.assertRaises(ValueError):retention.inspect(['absent-canary'])
        with self.assertRaises(ValueError):retention.open(SOURCE,SECOND)


if __name__ == '__main__': unittest.main()
