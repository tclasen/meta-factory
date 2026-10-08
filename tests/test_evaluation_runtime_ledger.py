"""Reconciliation cannot double-count counters or fabricate task/cost allocation."""
import copy
from datetime import datetime, timedelta, timezone
import json
import unittest
import uuid

from evaluation.runtime_ledger import summarize_runtime_events


class RuntimeLedgerTest(unittest.TestCase):
    def setUp(self):
        self.attempt=str(uuid.uuid4())
        self.records=[]
        self.add('controller','attempt.created',{})
        self.message('turn/started',dict(threadId='t',turn=dict(id='u')))

    def add(self, source, kind, payload):
        sequence=len(self.records)+1
        self.records.append(dict(schema_version=1,attempt_id=self.attempt,sequence=sequence,
            utc=(datetime(2026,10,8,tzinfo=timezone.utc)+timedelta(seconds=sequence)).isoformat(),
            elapsed_seconds=sequence,source=source,type=kind,payload=copy.deepcopy(payload)))

    def message(self, method, params):
        self.add('runtime','message',dict(method=method,params=params))

    def stage(self, identity='s', stage='planning', wp='WP-001'):
        self.message('item/tool/call',dict(threadId='t',turnId='u',callId=identity,
            tool='report_stage',arguments=dict(stage=stage,wp_id=wp)))

    def usage(self, value, **options):
        total=dict(inputTokens=value,outputTokens=value,cachedInputTokens=value//2,
                   reasoningOutputTokens=value//4,totalTokens=value*2)
        total.update(options)
        self.message('thread/tokenUsage/updated',dict(threadId='t',turnId='u',
            tokenUsage=dict(total=total,last=dict(total,inputTokens=1,outputTokens=1,totalTokens=2))))

    def summarize(self):
        return summarize_runtime_events(self.records,['WP-001','WP-002'])

    def test_cumulative_snapshots_duplicates_and_overlap_reconcile_exactly(self):
        self.stage();self.usage(10);self.usage(10);self.usage(30)
        result=self.summarize()
        self.assertEqual([r['usage_delta']['totalTokens'] for r in result['usage_intervals']],[20,0,40])
        self.assertEqual(result['usage_total']['totalTokens'],60)
        self.assertEqual(result['unallocated_usage'],result['usage_total'])
        self.assertTrue(result['usage_reconciled'])
        self.assertEqual(result['stage_token_allocation'],'unallocated')
        self.assertIsNone(result['monetary_estimate'])
        self.assertFalse(result['terminal_turn_observed'])
        self.assertEqual(result['usage_intervals'][0]['intervening_stage_markers'][0]['stage'],'planning')

    def test_stage_changes_reentry_and_duplicate_call_preserve_chronology(self):
        self.stage();self.usage(10)
        self.stage('implementation','implementation');self.stage('implementation','implementation')
        self.stage('other-work','review','WP-002');self.usage(20)
        self.stage('return','planning');self.usage(30)
        result=self.summarize()
        self.assertEqual([r['stage'] for r in result['stage_markers']],['planning','implementation','review','planning'])
        interval=result['usage_intervals'][1]
        self.assertEqual(interval['reported_stage_at_previous_snapshot'],dict(stage='planning',wp_id='WP-001'))
        self.assertEqual(interval['reported_stage_at_snapshot'],dict(stage='review',wp_id='WP-002'))
        self.assertEqual(len(interval['intervening_stage_markers']),2)
        self.assertEqual(result['unallocated_usage']['totalTokens'],60)

    def test_missing_usage_is_none_and_trailing_stage_is_not_zero_cost(self):
        self.stage()
        result=self.summarize()
        self.assertIsNone(result['usage_total']);self.assertIsNone(result['unallocated_usage'])
        self.assertFalse(result['usage_reconciled'])
        self.assertEqual(len(result['trailing_stage_markers']),1)
        self.assertEqual(result['usage_intervals'],[])

    def test_compactions_deduplicate_by_native_identity_and_keep_first_time(self):
        self.stage()
        event=dict(threadId='t',turnId='u',completedAtMs=1,item=dict(id='compact1',type='contextCompaction'))
        self.message('item/completed',event);self.message('item/completed',event)
        event['item']['id']='compact2';self.message('item/completed',event)
        result=self.summarize()
        self.assertEqual(result['compaction_count'],2)
        self.assertEqual([r['sequence'] for r in result['compactions']],[4,6])

    def test_foreign_thread_turn_or_repeated_terminal_event_refuse(self):
        baseline=copy.deepcopy(self.records)
        for mode in ('foreign-thread','foreign-turn','duplicate-final'):
            self.records=copy.deepcopy(baseline)
            if mode=='duplicate-final':
                final=dict(threadId='t',turn=dict(id='u',items=[],status='completed'))
                self.message('turn/completed',final);self.message('turn/completed',final)
            else:
                self.message('turn/started',dict(threadId='foreign' if mode=='foreign-thread' else 't',
                                                turn=dict(id='foreign' if mode=='foreign-turn' else 'u')))
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.summarize()

    def test_terminal_turn_and_raw_tool_content_do_not_grant_operator_completion(self):
        self.message('item/completed',dict(threadId='t',turnId='u',completedAtMs=1,
            item=dict(id='message',type='agentMessage',text='synthetic-secret-must-not-be-exported')))
        self.message('turn/completed',dict(threadId='t',turn=dict(id='u',items=[],status='completed')))
        result=self.summarize()
        self.assertTrue(result['terminal_turn_observed'])
        self.assertEqual(result['turn_status'],'completed')
        self.assertNotIn('synthetic-secret',json.dumps(result))
        self.assertNotIn('remote_termination_verified',result)

    def test_regression_boolean_unknown_or_changing_counter_sets_refuse(self):
        self.usage(10);baseline=copy.deepcopy(self.records)
        for mode in ('regression','boolean','unknown','new-optional'):
            self.records=copy.deepcopy(baseline)
            if mode=='regression':self.usage(5)
            elif mode=='boolean':self.usage(20,totalTokens=True)
            elif mode=='unknown':self.usage(20,undisclosedCounter=2)
            else:self.usage(20,cacheWriteInputTokens=0)
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.summarize()

    def test_optional_cache_write_counter_preserved_without_adding_to_totals(self):
        self.usage(10,cacheWriteInputTokens=5);self.usage(20,cacheWriteInputTokens=9)
        result=self.summarize()
        self.assertEqual(result['usage_total']['totalTokens'],40)
        self.assertEqual(result['usage_total']['cacheWriteInputTokens'],9)
        self.assertEqual(result['usage_intervals'][1]['usage_delta']['cacheWriteInputTokens'],4)

    def test_gap_attempt_mix_and_clock_or_metadata_corruption_refuse(self):
        baseline=copy.deepcopy(self.records)
        for mode in ('gap','attempt','elapsed','utc','schema','negative'):
            self.records=copy.deepcopy(baseline)
            row=self.records[-1]
            if mode=='gap':row['sequence']=9
            elif mode=='attempt':row['attempt_id']=str(uuid.uuid4())
            elif mode=='elapsed':row['elapsed_seconds']=float('nan')
            elif mode=='utc':row['utc']='2026-10-08T00:00:00'
            elif mode=='schema':row['schema_version']=True
            else:row['elapsed_seconds']=-0.5
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.summarize()

    def test_invalid_stage_package_and_conflicting_call_are_sanitized(self):
        baseline=copy.deepcopy(self.records)
        for mode in ('unknown-package','wrong-stage','conflict'):
            self.records=copy.deepcopy(baseline)
            if mode=='unknown-package':self.stage(wp='synthetic-private-identifier')
            elif mode=='wrong-stage':self.stage(stage=['synthetic-private-identifier'])
            else:self.stage();self.stage(stage='review')
            with self.subTest(mode=mode),self.assertRaises(ValueError) as caught:self.summarize()
            self.assertNotIn('synthetic-private',str(caught.exception))
