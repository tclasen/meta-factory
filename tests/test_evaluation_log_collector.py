"""Observed namespace identities connect to real Linux files without omission."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.log_collector import NamespaceLogCollector
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_pod_history import BINDING, history, pod, event, receipt
from test_evaluation_cri_follower import frame


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux inotify required')
class NamespaceCollectorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.h = history([pod()])
        self.r = PrivateCRIRetention(BINDING); self.addCleanup(self.r.close)
        self.ready, self.allowed, self.calls = True, True, []
        self.c = NamespaceLogCollector(self.h, self.r, self.resolve,
            check=lambda reserve:self.allowed, deadline=time.monotonic()+90)
        self.addCleanup(self.c.close)

    def resolve(self, entry, reserve):
        self.calls.append(entry)
        if not self.ready:return None
        return dict(directory=self.root/entry['source']['pod_uid'],node_uid='node-uid',
                    check=lambda source,reserve:self.allowed)

    def file(self, uid='pod-one', index=0, payload=b'private-canary'):
        directory=self.root/uid; directory.mkdir(exist_ok=True)
        path=directory/(str(index)+'.log'); path.write_bytes(frame(payload)); return path

    def test_discovery_deletion_and_recreation_capture_both_sources(self):
        path=self.file();self.assertEqual(self.c.poll()['attached_sources'],1)
        start=self.h.begin();self.h.accept(event(pod(),'DELETED'))
        self.h.accept(event(pod(uid='pod-two',current='containerd://two'),'ADDED'))
        self.h.finish(receipt(start,2)); self.file('pod-two',payload=b'second-canary')
        path.unlink()
        result=self.c.poll()
        self.assertEqual((result['attached_sources'],result['unresolved_sources']),(2,0))
        self.assertEqual(len(self.calls),2)
        self.assertTrue(self.r.inspect(binary_values=[b'private-canary'])['canary_present'])
        self.assertTrue(self.r.inspect(binary_values=[b'second-canary'])['canary_present'])
        self.assertFalse(result['history_complete'])
        self.assertNotIn('pod-one',repr(result))
        self.assertTrue(self.c.close()['descriptors_closed'])
        self.assertTrue(self.r.inspect(binary_values=[b'private-canary'])['canary_present'])

    def test_unresolved_and_pending_are_explicit_and_retried(self):
        self.ready=False
        self.assertEqual(self.c.poll()['unresolved_sources'],1)
        self.ready=True;self.file();self.assertEqual(self.c.poll()['unresolved_sources'],0)
        start=self.h.begin();value=pod(name='pending',uid='pending');value['status']={}
        self.h.accept(event(value,'ADDED'));self.h.finish(receipt(start,1))
        self.assertEqual(self.c.poll()['pending_containers'],1)
        self.assertEqual(self.c.summary()['attached_sources'],1)

    def test_summary_discloses_unattached_identities_before_and_between_polls(self):
        self.assertEqual(self.c.summary()['unresolved_sources'],1)
        self.file();self.c.poll()
        start=self.h.begin()
        self.h.accept(event(pod(name='new',uid='new',current='containerd://new'),'ADDED'))
        self.h.finish(receipt(start,1))
        self.assertEqual(self.c.summary()['unresolved_sources'],1)
        self.assertEqual(self.c.summary()['attached_sources'],1)

    def test_restart_selectors_do_not_duplicate_previous_source(self):
        self.file();self.c.poll();start=self.h.begin()
        self.h.accept(event(pod(count=1,current='containerd://two',prior='containerd://one')))
        self.h.finish(receipt(start,1));self.file(index=1,payload=b'restart-canary')
        self.assertEqual(self.c.poll()['attached_sources'],2)
        self.assertEqual(len(self.calls),2)
        self.assertTrue(self.r.inspect(binary_values=[b'restart-canary'])['canary_present'])

    def test_one_corrupted_file_stops_all_descriptors_preserves_positives(self):
        path=self.file();self.c.poll()
        descriptors=[value for f in self.c._followers.values()
                     for value in (f._dir_fd,f._notify_fd,f._current['fd'])]
        path.write_bytes(frame(b'overwritten'))
        with self.assertRaises(ValueError):self.c.poll()
        for fd in descriptors:
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertFalse(self.r.inspect(binary_values=[b'private-canary'])['retention_valid'])
        self.assertTrue(self.r.inspect(binary_values=[b'private-canary'])['canary_present'])
        with self.assertRaises(ValueError):self.c.poll()

    def test_guards_history_and_resolution_fail_closed(self):
        for failure in ('guard','history','resolve','deadline'):
            with self.subTest(failure=failure):
                h=history([pod()]);r=PrivateCRIRetention(BINDING)
                c=NamespaceLogCollector(h,r,lambda *args:dict(invalid='private-error'),
                    check=lambda reserve:failure!='guard',deadline=time.monotonic()+90)
                if failure=='history':h.abandon()
                if failure=='deadline':c._deadline=time.monotonic()
                with self.assertRaisesRegex(ValueError,'^Private namespace collection unavailable$'):c.poll()
                self.assertTrue(c.close()['descriptors_closed']);r.close()

    def test_binding_and_process_ownership_refused_before_lock(self):
        wrong=PrivateCRIRetention(dict(BINDING,uid='different'))
        self.addCleanup(wrong.close)
        with self.assertRaises(ValueError):NamespaceLogCollector(self.h,wrong,self.resolve,
            check=lambda reserve:True,deadline=time.monotonic()+90)
        with patch('evaluation.log_collector.os.getpid',return_value=-1):
            for operation in (self.c.poll,self.c.summary,self.c.close):
                with self.assertRaises(ValueError):operation()
