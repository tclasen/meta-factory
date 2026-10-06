"""Incomplete windows cannot advance/rebaseline a private watch cursor."""
import hashlib
import json
import unittest
from unittest.mock import patch

from evaluation.watch_cursor import PodWatchCursor


BINDING=dict(name='incident-app',uid='namespace-uid')
SECRET='Private-cursor-payload-secret'


def event(version,kind='MODIFIED'):
    metadata=dict(resourceVersion=version)
    if kind!='BOOKMARK':metadata.update(name='api',namespace='incident-app',uid='pod-uid',annotations={'secret':SECRET})
    return dict(type=kind,object=dict(apiVersion='v1',kind='Pod',metadata=metadata))


def receipt(start,count,**changes):
    value=dict(window_id=start['window_id'],outcome='watch_window_closed',events=count,
               binding_sha256=hashlib.sha256(json.dumps(BINDING,sort_keys=True).encode()).hexdigest(),
               anchor_sha256=hashlib.sha256(start['resource_version'].encode()).hexdigest(),
               source_verified_before=True,source_verified_after=True,client_group_absent=True)
    value.update(changes);return value


class WatchCursorTest(unittest.TestCase):
    def test_commit_resume_and_bookmark_cursor_are_opaque(self):
        cursor=PodWatchCursor(BINDING,'opaque-z')
        start=cursor.begin();cursor.accept(event('opaque-a'));cursor.accept(event('opaque-bookmark','BOOKMARK'))
        result=cursor.finish(receipt(start,2))
        self.assertEqual(cursor.resource_version,'opaque-bookmark')
        self.assertNotIn(SECRET,repr(result));self.assertNotIn('opaque-bookmark',repr(result))
        resumed=cursor.begin();self.assertEqual(resumed['resource_version'],'opaque-bookmark')
        self.assertNotEqual(start['window_id'],resumed['window_id'])
        cursor.finish(receipt(resumed,0));self.assertEqual(cursor.resource_version,'opaque-bookmark')

    def test_any_incomplete_or_foreign_window_permanently_invalidates(self):
        for change in (dict(outcome='incomplete'),dict(source_verified_after=False),dict(source_verified_before=1),
                       dict(client_group_absent=False),dict(events=True),dict(events=0),
                       dict(window_id='pod-watch-'+'0'*32),dict(binding_sha256='wrong'),dict(anchor_sha256='wrong')):
            cursor=PodWatchCursor(BINDING,'opaque');start=cursor.begin();cursor.accept(event('next'))
            with self.subTest(change=change),self.assertRaises(ValueError):cursor.finish(receipt(start,1,**change))
            with self.assertRaises(ValueError):cursor.begin()
            with self.assertRaises(ValueError):_ = cursor.resource_version

    def test_old_receipt_cannot_close_resumed_quiet_window(self):
        cursor=PodWatchCursor(BINDING,'opaque');start=cursor.begin();old=receipt(start,0);cursor.finish(old)
        cursor.begin()
        with self.assertRaises(ValueError):cursor.finish(old)
        with self.assertRaises(ValueError):cursor.begin()

    def test_missing_or_extra_consumer_events_refuse_commit(self):
        for observed,reported in ((0,1),(1,0),(2,1)):
            cursor=PodWatchCursor(BINDING,'opaque');start=cursor.begin()
            for index in range(observed):cursor.accept(event('event-'+str(index)))
            with self.assertRaises(ValueError):cursor.finish(receipt(start,reported))

    def test_abandon_overlap_or_late_event_cannot_rebaseline(self):
        for action in ('abandon','overlap','late'):
            cursor=PodWatchCursor(BINDING,'opaque');start=cursor.begin()
            if action=='abandon':cursor.abandon()
            elif action=='overlap':
                with self.assertRaises(ValueError):cursor.begin()
            else:
                cursor.finish(receipt(start,0))
                with self.assertRaises(ValueError):cursor.accept(event('late'))
            with self.assertRaises(ValueError):cursor.begin()

    def test_active_cursor_not_exposed_and_wrong_owner_refused(self):
        cursor=PodWatchCursor(BINDING,'opaque');start=cursor.begin()
        with self.assertRaises(ValueError):_ = cursor.resource_version
        cursor.finish(receipt(start,0))
        with patch('evaluation.watch_cursor.os.getpid',return_value=-1):
            with self.assertRaises(ValueError):cursor.begin()
        self.assertEqual(cursor.resource_version,'opaque')

    def test_malformed_or_scope_mismatched_event_invalidates_without_raw_error(self):
        for value in (dict(type='ERROR',object={'message':SECRET}),event(''),event('next')):
            if value.get('object',{}).get('metadata',{}).get('resourceVersion')=='next':value['object']['metadata']['namespace']='other'
            cursor=PodWatchCursor(BINDING,'opaque');cursor.begin()
            with self.assertRaisesRegex(ValueError,'^Private Pod watch cursor unavailable$'):cursor.accept(value)
            with self.assertRaises(ValueError):cursor.begin()

    def test_binding_is_copied_and_quiet_commit_has_no_history_claim(self):
        binding=dict(BINDING);cursor=PodWatchCursor(binding,'opaque');binding['uid']='changed'
        start=cursor.begin();result=cursor.finish(receipt(start,0))
        self.assertEqual(set(result),{'outcome','windows','events'})
        self.assertNotIn('history_complete',result)

    def test_zero_anchor_and_explicit_capacity_limits_refused(self):
        with self.assertRaises(ValueError):PodWatchCursor(BINDING,'0')
        cursor=PodWatchCursor(BINDING,'opaque');cursor.begin()
        with self.assertRaises(ValueError):cursor.accept(event('0','BOOKMARK'))
        cursor=PodWatchCursor(BINDING,'opaque');start=cursor.begin()
        with patch('evaluation.watch_cursor.MAX_EVENTS',1):
            cursor.accept(event('next'))
            with self.assertRaises(ValueError):cursor.accept(event('extra'))
        cursor=PodWatchCursor(BINDING,'opaque');start=cursor.begin();cursor.finish(receipt(start,0))
        with patch('evaluation.watch_cursor.MAX_WINDOWS',1):
            with self.assertRaises(ValueError):cursor.begin()


if __name__=='__main__':unittest.main()
