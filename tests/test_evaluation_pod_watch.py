"""Watch windows keep raw objects private and never self-attest full history."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.pod_watch import PodWatchTransport, watch_event


SECRET='Private-watch-annotation-secret'
BINDING=dict(name='incident-app',uid='namespace-uid')
CLIENT=r'''import json,signal,sys,time,urllib.parse
signal.alarm(5)
mode=sys.argv[1];path=sys.argv[3].removeprefix('--raw=');url=urllib.parse.urlsplit(path)
assert sys.argv[2]=='get' and url.path=='/api/v1/namespaces/incident-app/pods'
query=urllib.parse.parse_qs(url.query)
assert set(query)=={'watch','resourceVersion','allowWatchBookmarks','timeoutSeconds'}
assert query['resourceVersion']==['10&labelSelector=builder']
pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':'api','namespace':'incident-app','uid':'pod-uid','resourceVersion':'11','annotations':{'private':'Private-watch-annotation-secret'}}}
event={'type':'MODIFIED','object':pod}
if mode=='wrong-namespace':pod['metadata']['namespace']='other'
if mode=='watch-error':event={'type':'ERROR','object':{'kind':'Status','code':410,'message':'Private-watch-annotation-secret'}}
if mode=='duplicate':sys.stdout.write('{"type":"ADDED","type":"MODIFIED","object":{}}\n')
elif mode=='truncated':sys.stdout.write(json.dumps(event))
elif mode=='malformed':sys.stdout.write('Private-watch-annotation-secret\n')
elif mode=='large':sys.stdout.write('x'*1100000)
elif mode!='quiet':
 data=json.dumps(event)+'\n'
 sys.stdout.write(data[:7]);sys.stdout.flush();sys.stdout.write(data[7:])
 if mode=='bookmark':sys.stdout.write(json.dumps({'type':'BOOKMARK','object':{'apiVersion':'v1','kind':'Pod','metadata':{'resourceVersion':'12'}}})+'\n')
if mode=='diagnostics':sys.stderr.write('Private-watch-annotation-secret')
sys.stdout.flush();sys.stderr.flush()
if mode=='failed':sys.exit(7)
if mode=='hang':time.sleep(5)
'''


class PodWatchTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.attempt=Attempt(self.root/'attempt',{})
        self.addCleanup(self.attempt.close);self.allowed=True;self.checks=[]
        self.client=self.root/'client.py';self.client.write_text(CLIENT)

    def guard(self,binding,reserve):
        self.checks.append((binding,reserve));return self.allowed

    def transport(self,mode):
        return PodWatchTransport(self.attempt,[sys.executable,str(self.client),mode],BINDING,
                                 resource_version='10&labelSelector=builder',check=self.guard,cwd=self.root)

    def assert_private(self):
        for path in self.attempt.directory.rglob('*'):
            if path.is_file():self.assertNotIn(SECRET.encode(),path.read_bytes())

    def test_private_split_events_bookmarks_and_scope_quoting(self):
        values=[];result=self.transport('bookmark')(values.append,timeout=1)
        self.assertEqual(result['outcome'],'watch_window_closed')
        self.assertEqual([v['type'] for v in values],['MODIFIED','BOOKMARK'])
        self.assertEqual(result['events'],2);self.assertTrue(result['client_group_absent'])
        self.assertEqual(self.checks,[(BINDING,6),(BINDING,5)])
        self.assert_private()

    def test_malformed_expired_truncated_or_oversized_watch_is_incomplete(self):
        for mode in ('wrong-namespace','watch-error','duplicate','truncated','malformed','large','failed','hang'):
            with self.subTest(mode=mode):
                result=self.transport(mode)(lambda value:None,timeout=.2 if mode=='hang' else 1)
                self.assertEqual(result['outcome'],'incomplete')
                self.assertTrue(result['client_group_absent'])
                self.assert_private()

    def test_private_client_diagnostics_are_discarded(self):
        result=self.transport('diagnostics')(lambda value:None,timeout=1)
        self.assertEqual(result['outcome'],'watch_window_closed')
        self.assertGreater(result['stderr_bytes'],0);self.assert_private()

    def test_precheck_failure_starts_no_client(self):
        self.allowed=False
        result=self.transport('bookmark')(lambda value:None,timeout=1)
        self.assertEqual(result['outcome'],'incomplete');self.assertNotIn('client_group',result)

    def test_postcheck_loss_suppresses_complete_window(self):
        def consume(value):self.allowed=False
        result=self.transport('bookmark')(consume,timeout=1)
        self.assertEqual(result['outcome'],'incomplete');self.assertFalse(result['source_verified_after'])
        self.assertTrue(result['client_group_absent'])

    def test_consumer_exception_is_sanitized_and_client_disposed(self):
        def consume(value):raise RuntimeError(SECRET)
        result=self.transport('bookmark')(consume,timeout=1)
        self.assertEqual(result['outcome'],'incomplete');self.assertEqual(result['error_type'],'RuntimeError')
        self.assertTrue(result['client_group_absent']);self.assert_private()

    def test_quiet_window_is_not_history_attestation(self):
        result=self.transport('quiet')(lambda value:None,timeout=1)
        self.assertEqual(result['outcome'],'watch_window_closed');self.assertEqual(result['events'],0)
        self.assertNotIn('history_complete',result);self.assertNotIn('verdict',result)

    def test_bad_bounds_scope_and_event_shapes_refused(self):
        for binding in (dict(BINDING,name='other/namespace'),dict(BINDING,uid=''),dict(BINDING,extra='secret')):
            with self.assertRaises(ValueError):
                PodWatchTransport(self.attempt,['unused'],binding,resource_version='1',check=self.guard,cwd=self.root)
        for timeout in (True,0,31,float('inf')):
            with self.assertRaises(ValueError):self.transport('quiet')(lambda value:None,timeout=timeout)
        for value in ({'type':'MODIFIED','object':{}},{'type':'BOOKMARK','object':{'apiVersion':'v1','kind':'Pod','metadata':{}}}):
            with self.assertRaises(ValueError):watch_event(json.dumps(value),'incident-app')


if __name__=='__main__':unittest.main()
