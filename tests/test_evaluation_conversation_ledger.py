"""Conversation ledgers bind controlled turns and reconcile thread counters."""
import copy
import json
import unittest

from evaluation.runtime_ledger import summarize_runtime_events
import test_evaluation_runtime_ledger as ledger_fixture
import test_evaluation_conversation as conversation_fixture


class ConversationLedgerTest(unittest.TestCase):
    def setUp(self):
        self.fixture=ledger_fixture.RuntimeLedgerTest();self.fixture.setUp()
        self.fixture.records.pop()  # Replace implicit single-turn start with control evidence.
        self.request(3)
        self.start('u')

    def request(self, identifier, thread='t'):
        self.fixture.add('controller','builder.request',dict(thread_id=thread,request_id=identifier))

    def start(self, turn, thread='t'):
        self.fixture.message('turn/started',dict(threadId=thread,turn=dict(id=turn)))

    def end(self, turn, status='completed'):
        self.fixture.message('turn/completed',dict(threadId='t',turn=dict(id=turn,items=[],status=status)))

    def usage(self, turn, count):
        values=dict(inputTokens=count,outputTokens=count,totalTokens=count*2,
                    cachedInputTokens=count//2,reasoningOutputTokens=count//4)
        self.fixture.message('thread/tokenUsage/updated',dict(threadId='t',turnId=turn,
            tokenUsage=dict(total=values,last=values)))

    def terminal(self, turn='u', status='complete', identity='finish', reason='secret-terminal-reason'):
        self.fixture.message('item/tool/call',dict(threadId='t',turnId=turn,callId=identity,
            tool='finish_workload',arguments=dict(status=status,reason=reason)))

    def summarize(self):
        return summarize_runtime_events(self.fixture.records,['WP-001','WP-002'],conversation=True)

    def test_cumulative_usage_and_stage_context_across_two_turns(self):
        self.fixture.stage();self.usage('u',10);self.end('u');self.request(5);self.start('v')
        self.fixture.message('item/tool/call',dict(threadId='t',turnId='v',callId='second',
            tool='report_stage',arguments=dict(stage='implementation',wp_id='WP-002')))
        self.usage('v',30);self.usage('v',30);self.terminal('v');self.end('v')
        result=self.summarize()
        self.assertEqual(result['usage_total']['totalTokens'],60)
        self.assertEqual([r['usage_delta']['totalTokens'] for r in result['usage_intervals']],[20,40,0])
        self.assertEqual([r['turn_id'] for r in result['usage_intervals']],['u','v','v'])
        self.assertEqual([r['turn_id'] for r in result['turns']],['u','v'])
        self.assertTrue(result['conversation_terminal_observed'])
        self.assertEqual(result['workload_declaration']['status'],'complete')
        self.assertNotIn('secret-terminal-reason',json.dumps(result))
        self.assertEqual(result['unallocated_usage'],result['usage_total'])
        self.assertIsNone(result['monetary_estimate'])
        self.assertNotIn('accepted_packages',result)

    def test_live_prefix_end_of_turn_does_not_end_workload(self):
        self.end('u');result=self.summarize()
        self.assertTrue(result['terminal_turn_observed'])
        self.assertFalse(result['conversation_terminal_observed'])
        self.request(5);result=self.summarize()
        self.assertIsNone(result['turn_requests'][-1]['turn_id'])
        self.assertFalse(result['conversation_terminal_observed'])
        self.start('v');self.terminal('v');result=self.summarize()
        self.assertFalse(result['conversation_terminal_observed'])
        self.end('v');self.assertTrue(self.summarize()['conversation_terminal_observed'])

    def test_native_responses_can_bind_before_started_notification(self):
        records=self.fixture.records[:2]
        self.fixture.records=records
        self.fixture.add('runtime','message',dict(id=3,result=dict(turn=dict(id='u'))))
        self.start('u');self.end('u');self.request(5)
        self.fixture.add('runtime','message',dict(id=5,result=dict(turn=dict(id='v'))))
        self.start('v');self.usage('v',20)
        self.assertEqual(self.summarize()['usage_total']['totalTokens'],40)

    def test_duplicate_completion_and_late_compaction_are_not_double_counted(self):
        self.end('u');self.end('u');self.request(5);self.start('v')
        event=dict(threadId='t',turnId='u',completedAtMs=1,item=dict(id='compact',type='contextCompaction'))
        self.fixture.message('item/completed',event);self.fixture.message('item/completed',event)
        result=self.summarize()
        self.assertEqual(result['compaction_count'],1)
        self.assertEqual(result['compactions'][0]['turn_id'],'u')
        self.assertEqual(result['turn_id'],'v')
        self.assertFalse(result['terminal_turn_observed'])

    def test_declarations_quota_and_interruption_are_terminal_not_acceptance(self):
        baseline=copy.deepcopy(self.fixture.records)
        for declaration,status in [('complete','completed'),('blocked','completed'),(None,'failed'),(None,'interrupted')]:
            self.fixture.records=copy.deepcopy(baseline)
            if declaration:self.terminal(status=declaration)
            self.end('u',status);self.assertTrue(self.summarize()['conversation_terminal_observed'])
            self.request(5)
            with self.assertRaises(ValueError):self.summarize()

    def test_uncontrolled_foreign_or_concurrent_turns_refuse(self):
        baseline=copy.deepcopy(self.fixture.records)
        for mode in ['unknown-turn','foreign-thread','concurrent-request','wrong-request-id','unknown-response','turn-reuse']:
            self.fixture.records=copy.deepcopy(baseline)
            if mode=='unknown-turn':self.start('v')
            if mode=='foreign-thread':self.start('u','foreign')
            if mode=='concurrent-request':self.request(5)
            if mode=='wrong-request-id':self.end('u');self.request(6)
            if mode=='unknown-response':self.fixture.add('runtime','message',dict(id=99,result=dict(turn=dict(id='v'))))
            if mode=='turn-reuse':
                self.end('u');self.request(5);self.fixture.add('runtime','message',dict(id=5,result=dict(turn=dict(id='u'))))
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.summarize()

    def test_conflicting_terminal_calls_closed_turn_calls_and_counter_resets_refuse(self):
        baseline=copy.deepcopy(self.fixture.records)
        for mode in ['conflict','call-reuse','closed-turn','counter-reset','conflicting-end','duplicate-response']:
            self.fixture.records=copy.deepcopy(baseline)
            if mode=='conflict':self.terminal();self.terminal(status='blocked',identity='other')
            if mode=='call-reuse':self.fixture.stage(identity='finish');self.terminal()
            if mode=='closed-turn':self.end('u');self.terminal()
            if mode=='counter-reset':self.usage('u',20);self.end('u');self.request(5);self.start('v');self.usage('v',10)
            if mode=='conflicting-end':self.end('u');self.end('u','failed')
            if mode=='duplicate-response':
                self.fixture.add('runtime','message',dict(id=3,result=dict(turn=dict(id='u'))))
                self.fixture.add('runtime','message',dict(id=3,result=dict(turn=dict(id='u'))))
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.summarize()

    def test_missing_control_evidence_and_nonboolean_mode_refuse(self):
        self.fixture.records.pop(1)
        for index,row in enumerate(self.fixture.records,1):row['sequence']=index
        with self.assertRaises(ValueError):self.summarize()
        with self.assertRaises(ValueError):summarize_runtime_events(self.fixture.records,['WP-001'],conversation=1)

    def test_actual_three_turn_subprocess_stream_projects_without_acceptance(self):
        runtime,events=conversation_fixture.ConversationTest().transport(3)
        ledger=summarize_runtime_events(events,['WP-001'],conversation=True)
        self.assertEqual([r['turn_id'] for r in ledger['turns']],runtime['turn_ids'])
        self.assertTrue(ledger['conversation_terminal_observed'])
        self.assertEqual(ledger['workload_declaration']['status'],'complete')
        self.assertIsNone(ledger['usage_total'])
        self.assertEqual(ledger['compaction_count'],runtime['compaction_item_count'])


if __name__=='__main__':unittest.main()
