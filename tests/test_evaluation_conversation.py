"""Continuous same-thread protocol and real bounded subprocess transport."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.runtime import Conversation, run_session


class ConversationTest(unittest.TestCase):
    def running(self, **options):
        session = Conversation('/work', 'whole workload', ['WP-001'],
                               continuation_prompt='Continue the same whole workload.', **options)
        self.assertTrue(session.initial()['params']['capabilities']['experimentalApi'])
        replies = session.receive(dict(id=1, result={}))
        names = [t['name'] for t in replies[1]['params']['dynamicTools']]
        self.assertIn('finish_workload', names)
        self.assertEqual('report_stage' in names, options.get('stage_tool', False))
        session.receive(dict(id=2, result=dict(thread=dict(id='t'))))
        session.receive(dict(id=3, result=dict(turn=dict(id='u'))))
        return session

    def completed(self, identity='u', status='completed', error=None):
        turn = dict(id=identity, status=status, items=[])
        if error:
            turn['error'] = dict(message='synthetic', codexErrorInfo=error)
        return dict(method='turn/completed', params=dict(threadId='t', turn=turn))

    def declare(self, session, status='complete', **overrides):
        params = dict(threadId='t', turnId=session.turn, callId='terminal', tool='finish_workload',
                      arguments=dict(status=status, reason='Synthetic terminal facts'))
        params.update(overrides)
        return session.receive(dict(id=100, method='item/tool/call', params=params))

    def test_incomplete_turn_continues_in_same_thread_with_frozen_prompt(self):
        s = self.running(stage_tool=True)
        requests = s.receive(self.completed())
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0], dict(id=5, method='turn/start', params=dict(
            threadId='t', input=[dict(type='text', text=s.continuation_prompt)],
            model='gpt-6-luna', effort='medium', approvalPolicy='never')))
        self.assertIsNone(s.outcome)
        self.assertEqual(s.phase, 'starting_turn')
        # Notification may precede the RPC response.
        s.receive(dict(method='turn/started', params=dict(threadId='t', turn=dict(id='v'))))
        s.receive(dict(id=5, result=dict(turn=dict(id='v'))))
        self.declare(s)
        self.assertEqual(s.receive(self.completed('v')), [])
        result = s.result()
        self.assertEqual(result['outcome'], 'completed')
        self.assertEqual(result['turn_ids'], ['u', 'v'])
        self.assertEqual(result['continuation_count'], 1)
        self.assertEqual(result['workload_declared_status'], 'complete')
        self.assertFalse(result['remote_termination_verified'])
        self.assertNotIn('Synthetic terminal facts', json.dumps(result))

    def test_duplicate_terminal_event_never_enqueues_another_turn(self):
        s = self.running();event = self.completed()
        self.assertEqual(len(s.receive(event)), 1)
        self.assertEqual(s.receive(event), [])
        with self.assertRaises(ValueError):
            s.receive(self.completed(status='failed'))
        self.assertEqual(s.continuation_count, 1)

    def test_completed_or_blocked_declaration_stops_before_three_compactions(self):
        for status, outcome in [('complete', 'completed'), ('blocked', 'builder_declared_blocked')]:
            s = self.running();first = self.declare(s, status)
            self.assertEqual(first, self.declare(s, status))
            self.assertEqual(s.receive(self.completed()), [])
            self.assertEqual(s.outcome, outcome)
            self.assertEqual(s.result()['compaction_item_count'], 0)

    def test_invalid_conflicting_or_foreign_terminal_reports_fail_closed(self):
        for arguments in [dict(status='in-progress', reason='x'), dict(status='complete', reason=' '),
                          dict(status='complete', reason='x'*2001),
                          dict(status='complete', reason='x', extra=True)]:
            s = self.running();reply = self.declare(s, arguments=arguments)
            self.assertFalse(reply[0]['result']['success'])
            self.assertEqual(s.receive(self.completed()), [])
            self.assertEqual(s.outcome, 'protocol_violation')
        s = self.running();self.declare(s)
        with self.assertRaises(ValueError):self.declare(s, 'blocked')
        s = self.running()
        with self.assertRaises(ValueError):self.declare(s, threadId='other')
        s = self.running()
        with self.assertRaises(ValueError):self.declare(s, turnId='other')

    def test_quota_failure_approval_and_timeout_never_continue(self):
        for status, error, outcome in [('failed','usageLimitExceeded','quota_incomplete'),
                                       ('failed','other','builder_failure'),
                                       ('interrupted',None,'interrupted_incomplete')]:
            s = self.running()
            self.assertEqual(s.receive(self.completed(status=status, error=error)), [])
            self.assertEqual(s.outcome, outcome)
        s = self.running();s.interrupt();self.declare(s)
        self.assertEqual(s.receive(self.completed()), [])
        self.assertEqual(s.outcome, 'timeout_incomplete')
        s = self.running()
        s.receive(dict(id=50, method='item/commandExecution/requestApproval', params={}))
        self.assertEqual(s.receive(self.completed()), [])
        self.assertEqual(s.outcome, 'execution_boundary_incomplete')

    def test_stale_rpc_unknown_ids_and_turn_identity_reuse_are_rejected(self):
        for identifier in [3, 9, True, '5']:
            s = self.running();s.receive(self.completed())
            with self.assertRaises(ValueError):s.receive(dict(id=identifier, result=dict(turn=dict(id='v'))))
        s = self.running();s.receive(self.completed())
        with self.assertRaises(ValueError):s.receive(dict(id=5, result=dict(turn=dict(id='u'))))

    def test_initial_rpc_error_and_conflicting_second_declaration_stop(self):
        s=Conversation('/work','whole workload',['WP-001'],continuation_prompt='Continue.')
        self.assertEqual(s.receive(dict(id=1,error=dict(code=-1,message='Synthetic failure'))),[])
        self.assertEqual(s.outcome,'infrastructure_incomplete')
        s=self.running();self.declare(s)
        reply=self.declare(s,'blocked',callId='another-terminal')
        self.assertFalse(reply[0]['result']['success'])
        self.assertEqual(s.receive(self.completed()),[])
        self.assertEqual(s.outcome,'protocol_violation')

    def test_thread_cumulative_usage_and_late_compaction_remain_bound(self):
        s = self.running()
        def usage(turn, total):
            values=dict(inputTokens=total, outputTokens=0, cachedInputTokens=0,
                        reasoningOutputTokens=0, totalTokens=total)
            return dict(method='thread/tokenUsage/updated', params=dict(threadId='t',turnId=turn,
                tokenUsage=dict(total=values,last=values)))
        s.receive(usage('u',10));s.receive(self.completed())
        s.receive(dict(id=5,result=dict(turn=dict(id='v'))))
        event=dict(method='item/completed',params=dict(threadId='t',turnId='u',completedAtMs=1,
            item=dict(id='compaction',type='contextCompaction')))
        s.receive(event);s.receive(event);s.receive(usage('v',15))
        self.assertEqual(s.result()['usage_total']['totalTokens'],15)
        self.assertEqual(s.result()['compaction_item_count'],1)
        with self.assertRaises(ValueError):s.receive(usage('unknown',20))
        with self.assertRaises(ValueError):s.receive(usage('u',9))

    def test_empty_or_unbounded_continuation_is_refused(self):
        for value in ['', ' ', None, 'x'*65537]:
            with self.assertRaises(ValueError):
                Conversation('/work','x',['WP-001'],continuation_prompt=value)

    def transport(self, finish_after, delay=0, builder_seconds=2):
        code = '''import sys,json,time
n=0
def send(m):print(json.dumps(m),flush=True)
for line in sys.stdin:
 m=json.loads(line);method=m.get('method')
 if method=='initialize':send({'id':m['id'],'result':{}})
 if method=='thread/start':send({'id':m['id'],'result':{'thread':{'id':'t'}}})
 if method=='turn/start':
  n+=1;turn='u'+str(n)
  assert m['params']['threadId']=='t'
  send({'id':m['id'],'result':{'turn':{'id':turn}}})
  time.sleep(DELAY)
  if n>=FINISH:
   send({'id':100,'method':'item/tool/call','params':{'threadId':'t','turnId':turn,'callId':'terminal','tool':'finish_workload','arguments':{'status':'complete','reason':'Synthetic finish'}}})
  else:send({'method':'turn/completed','params':{'threadId':'t','turn':{'id':turn,'items':[],'status':'completed'}}})
 if m.get('id')==100 and 'result' in m:
  send({'method':'turn/completed','params':{'threadId':'t','turn':{'id':turn,'items':[],'status':'completed'}}})
 if method=='turn/interrupt':
  send({'id':m['id'],'result':{}})
  send({'method':'turn/completed','params':{'threadId':'t','turn':{'id':m['params']['turnId'],'items':[],'status':'interrupted'}}})
'''.replace('DELAY',repr(delay)).replace('FINISH',repr(finish_after))
        with tempfile.TemporaryDirectory() as directory:
            with Attempt(Path(directory)/'attempt',{}) as attempt:
                result=run_session(attempt,[sys.executable,'-u','-c',code],
                    Conversation('/work','whole workload',['WP-001'],continuation_prompt='Continue.'),
                    cwd=directory,builder_seconds=builder_seconds,setup_seconds=1,grace_seconds=.1)
                events=[json.loads(line) for line in (attempt.directory/'events.jsonl').read_text().splitlines()]
                return result,events

    def test_actual_subprocess_continues_then_stops_on_declaration(self):
        result,events=self.transport(3)
        self.assertEqual(result['outcome'],'completed')
        self.assertEqual(result['turn_ids'],['u1','u2','u3'])
        self.assertEqual(result['continuation_count'],2)
        self.assertEqual(len([r for r in events if r['type']=='builder.request']),3)
        self.assertIsNone(result['runtime_failure'])

    def test_conversation_deadline_is_not_reset_by_each_new_turn(self):
        result,events=self.transport(30,delay=.04,builder_seconds=.18)
        self.assertEqual(result['outcome'],'timeout_incomplete')
        self.assertGreater(result['continuation_count'],1)
        self.assertLess(result['continuation_count'],29)
        self.assertLess(result['timing']['builder_elapsed_seconds'],.8)
        self.assertEqual(result['timing']['local_cleanup_outcome'],'settled')


if __name__ == '__main__':unittest.main()
