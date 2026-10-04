"""Pinned-protocol fixtures, never live inference."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.runtime import Session, run_session, validate


class RuntimeTest(unittest.TestCase):
    def running(self, **kwargs):
        session = Session("/work", "fixture", ["WP-001"], **kwargs)
        validate("InitializeParams", session.initial()["params"])
        self.assertEqual(session.receive({"id": 1, "result": {}})[1]["method"], "thread/start")
        self.assertEqual(session.receive({"id": 2, "result": {"thread": {"id": "t"}}})[0]["method"], "turn/start")
        session.receive({"id": 3, "result": {"turn": {"id": "u"}}})
        return session

    def final(self, status="completed", code=None):
        turn = {"id": "u", "items": [], "status": status}
        if code:
            turn["error"] = {"message": "fixture", "codexErrorInfo": code}
        return {"method": "turn/completed", "params": {"threadId": "t", "turn": turn}}

    def test_one_turn_only_and_duplicate_response_rejected(self):
        session = self.running()
        self.assertEqual(session.receive(self.final()), [])
        self.assertEqual(session.result()["outcome"], "completed")
        with self.assertRaises(ValueError):
            session.receive({"id": 2, "result": {"thread": {"id": "second"}}})

    def test_compaction_dedup_and_foreign_event_rejected(self):
        session = self.running()
        event = {"method": "item/completed", "params": {"threadId": "t", "turnId": "u", "completedAtMs": 1,
                 "item": {"id": "c", "type": "contextCompaction"}}}
        session.receive(event)
        session.receive(event)
        self.assertEqual(session.result()["compaction_item_count"], 1)
        event["params"]["threadId"] = "foreign"
        with self.assertRaises(ValueError):
            session.receive(event)

    def test_usage_is_latest_total_not_sum_and_missing_is_none(self):
        session = self.running()
        self.assertIsNone(session.result()["usage_total"])
        total = {"inputTokens": 10, "outputTokens": 5, "cachedInputTokens": 2,
                 "reasoningOutputTokens": 1, "totalTokens": 15}
        event = {"method": "thread/tokenUsage/updated", "params": {"threadId": "t", "turnId": "u",
                 "tokenUsage": {"total": total, "last": total}}}
        session.receive(event)
        session.receive(event)
        self.assertEqual(session.result()["usage_total"]["totalTokens"], 15)
        event["params"]["tokenUsage"]["total"] = dict(total, totalTokens=14)
        with self.assertRaises(ValueError):
            session.receive(event)

    def test_quota_separate_from_builder_failure(self):
        for code, outcome in [("usageLimitExceeded", "quota_incomplete"), ("other", "builder_failure")]:
            session = self.running()
            session.receive(self.final("failed", code))
            self.assertEqual(session.outcome, outcome)

    def test_deadline_cannot_become_success(self):
        session = self.running()
        self.assertEqual(session.interrupt()["method"], "turn/interrupt")
        session.receive(self.final())
        self.assertEqual(session.outcome, "timeout_incomplete")

    def test_unexpected_approval_is_refused(self):
        session = self.running()
        replies = session.receive({"id": 50, "method": "item/commandExecution/requestApproval", "params": {}})
        self.assertIn("error", replies[0])
        self.assertEqual(session.outcome, "execution_boundary_incomplete")
        session.receive(self.final())
        self.assertEqual(session.outcome, "execution_boundary_incomplete")

    def test_stage_tool_is_write_only_constant_ack_and_deduplicated(self):
        session = self.running(stage_tool=True)
        params = {"threadId": "t", "turnId": "u", "callId": "c", "tool": "report_stage",
                  "arguments": {"stage": "implementation", "wp_id": "WP-001"}}
        event = {"id": 10, "method": "item/tool/call", "params": params}
        reply = session.receive(event)
        self.assertEqual(reply, session.receive(event))
        self.assertEqual(len(session.stage_events), 1)
        params["arguments"] = {"stage": "read_previous", "wp_id": "WP-001"}
        session.receive(event)
        self.assertEqual(session.outcome, "protocol_violation")

    def transport(self, code, **options):
        with tempfile.TemporaryDirectory() as name:
            with Attempt(Path(name) / "attempt", {}) as attempt:
                return run_session(attempt, [sys.executable, "-u", "-c", code],
                    Session("/work", "fixture", ["WP-001"]), cwd=name,
                    builder_seconds=options.pop("builder_seconds", 1), setup_seconds=0.5,
                    grace_seconds=0.1, **options)

    def test_malformed_and_oversized_output_never_pass(self):
        for code in ["print('not json')", "print('x'*10000)"]:
            result = self.transport(code, max_stream_bytes=1000)
            self.assertEqual(result["outcome"], "infrastructure_incomplete")

    def test_silent_server_is_bounded_without_remote_termination_claim(self):
        result = self.transport("import time; time.sleep(60)")
        self.assertEqual(result["outcome"], "timeout_incomplete")
        self.assertFalse(result["remote_termination_verified"])

    def test_fake_server_complete_transport(self):
        code = '''import sys,json
for line in sys.stdin:
 m=json.loads(line)
 if m.get('method')=='initialize':print(json.dumps({'id':m['id'],'result':{}}),flush=True)
 if m.get('method')=='thread/start':print(json.dumps({'id':m['id'],'result':{'thread':{'id':'t'}}}),flush=True)
 if m.get('method')=='turn/start':
  print(json.dumps({'id':m['id'],'result':{'turn':{'id':'u'}}}),flush=True)
  print(json.dumps({'method':'turn/completed','params':{'threadId':'t','turn':{'id':'u','items':[],'status':'completed'}}}),flush=True)
'''
        self.assertEqual(self.transport(code)["outcome"], "completed")
