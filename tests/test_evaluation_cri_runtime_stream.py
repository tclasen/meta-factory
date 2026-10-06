"""Fragmentation is allowed; ambiguity/truncation cannot leave admitted data valid."""
import json
import unittest
from unittest.mock import patch

from evaluation.cri_runtime_stream import PrivateCRIEventDecoder
from test_evaluation_cri_runtime_event import runtime_event


class CRIStreamTest(unittest.TestCase):
    def setUp(self):
        self.values=[]; self.invalidated=False; self.allowed=True
        def invalidate():self.invalidated=True;self.values.clear()
        self.decoder=PrivateCRIEventDecoder(self.values.append,check=lambda _:self.allowed,invalidate=invalidate)
        self.addCleanup(self.decoder.close)

    def test_bytewise_unicode_and_pretty_objects_admit_before_finish(self):
        v=runtime_event();v['private']='unicode \u00e9 \U0001f600'
        raw=(json.dumps(v,ensure_ascii=False,indent=2)+'\n'+json.dumps(v)).encode()
        for byte in raw:self.decoder.feed(bytes([byte]))
        self.assertEqual(self.values,[v,v])
        self.assertFalse(self.decoder.summary()['window_finished'])
        self.assertTrue(self.decoder.finish()['window_finished'])
        self.assertFalse(self.decoder.summary()['history_complete'])

    def test_admitted_prefix_is_invalidated_by_truncated_suffix(self):
        self.decoder.feed(json.dumps(runtime_event()).encode()+b' {"private":')
        self.assertEqual(len(self.values),1)
        with self.assertRaisesRegex(ValueError,'^Private CRI stream unavailable$') as failure:self.decoder.finish()
        self.assertEqual(failure.exception.reason,'framing')
        self.assertTrue(self.invalidated);self.assertEqual(self.values,[])
        self.assertTrue(self.decoder.summary()['dependents_invalidated'])
        with self.assertRaises(ValueError):self.decoder.feed(b'{}')

    def test_duplicate_nonfinite_scalar_and_bad_utf8_refuse_privately(self):
        for raw in (b'{"secret":1,"secret":2}',b'{"secret":NaN}',b'[]',b'null',b'\xff'):
            values=[];closed=[]
            d=PrivateCRIEventDecoder(values.append,check=lambda _:True,invalidate=lambda:closed.append(True))
            try:
                with self.assertRaisesRegex(ValueError,'^Private CRI stream unavailable$'):d.feed(raw)
                self.assertEqual(values,[]);self.assertEqual(closed,[True])
            finally:d.close()

    def test_guard_callback_and_cleanup_failures_cannot_pass(self):
        self.allowed=False
        with self.assertRaises(ValueError):self.decoder.feed(b'{}')
        self.assertTrue(self.invalidated)
        def fail(*_):raise ValueError('private diagnostic')
        for consume,invalidate in ((fail,lambda:None),(lambda _:None,fail)):
            d=PrivateCRIEventDecoder(consume,check=lambda _:True,invalidate=invalidate)
            try:
                if consume is fail:
                    with self.assertRaisesRegex(ValueError,'^Private CRI stream unavailable$'):d.feed(b'{}')
                else:
                    result=d.close();self.assertFalse(result['valid']);self.assertFalse(result['dependents_invalidated'])
            finally:d.close()

    def test_numeric_overflow_invalidates_prior_admission_before_consumer(self):
        for suffix in (b'400}', b'9999,"nested":[1]}'):
            values=[];closed=[]
            def invalidate():closed.append(True);values.clear()
            d=PrivateCRIEventDecoder(values.append,check=lambda _:True,invalidate=invalidate)
            try:
                d.feed(b'{"finite":1e308}')
                self.assertEqual(len(values),1)
                d.feed(b'{"private":-1e')
                with self.assertRaisesRegex(ValueError,'^Private CRI stream unavailable$'):
                    d.feed(suffix)
                self.assertEqual(values,[]);self.assertEqual(closed,[True])
                self.assertTrue(d.summary()['dependents_invalidated'])
            finally:d.close()

    def test_bounds_invalidate_without_retaining_input(self):
        for constant,value,raw in (('MAX_EVENT_BYTES',1,b'{}'),('MAX_STREAM_BYTES',1,b'{}'),('MAX_EVENTS',0,b'{}'),('MAX_CHUNK_BYTES',1,b'{}')):
            closed=[];d=PrivateCRIEventDecoder(lambda _:None,check=lambda _:True,invalidate=lambda:closed.append(True))
            try:
                with patch('evaluation.cri_runtime_stream.'+constant,value):
                    with self.assertRaises(ValueError):d.feed(raw)
                self.assertEqual(d._text,'');self.assertEqual(closed,[True])
            finally:d.close()

    def test_finish_rejects_incomplete_utf8_and_feed_after_finish(self):
        self.decoder.feed(b'{"x":"\xc3')
        with self.assertRaises(ValueError):self.decoder.finish()
        self.assertTrue(self.invalidated)
        closed=[];d=PrivateCRIEventDecoder(lambda _:None,check=lambda _:True,invalidate=lambda:closed.append(True))
        try:
            d.feed(b'{}');d.finish()
            with self.assertRaises(ValueError):d.feed(b'{}')
            self.assertEqual(closed,[True])
        finally:d.close()

    def test_empty_window_is_framing_only_and_close_invalidates(self):
        result=self.decoder.finish()
        self.assertEqual(result['events'],0);self.assertFalse(result['history_complete'])
        self.decoder.close();self.assertTrue(self.invalidated)
