"""Pinned Codex 0.160.0 single-thread/turn adapter. No model launch CLI."""

from collections import deque
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

from jsonschema import Draft7Validator

from .evidence import kill_group, positive, private_file


SCHEMA_DIR = Path(__file__).with_name("schema")
SCHEMA_BYTES = (SCHEMA_DIR / "codex-0.160.0.json").read_bytes()
PROVENANCE = json.loads((SCHEMA_DIR / "provenance.json").read_text())
if hashlib.sha256(SCHEMA_BYTES).hexdigest() != PROVENANCE["selection_sha256"]:
    raise RuntimeError("Pinned protocol schema changed")
SCHEMAS = {name: Draft7Validator(schema) for name, schema in json.loads(SCHEMA_BYTES).items()}
STAGES = ("planning", "implementation", "verification", "review")


def validate(name, value):
    SCHEMAS[name].validate(value)


def request(identifier, method, params, schema):
    validate(schema, params)
    return {"id": identifier, "method": method, "params": params}


class Session:
    """Pure state machine: duplicate events never cause another turn or request."""
    def __init__(self, cwd, prompt, packages, *, stage_tool=False):
        if not packages or len(packages) != len(set(packages)):
            raise ValueError("Unique package IDs required")
        self.cwd, self.prompt, self.packages = cwd, prompt, packages
        self.stage_tool = stage_tool
        self.thread = self.turn = None
        self.phase = "initializing"
        self.outcome = None
        self.compactions = set()
        self.usage = None
        self.stage_events = []
        self.calls = {}
        self.responses = set()
        self.interrupted = False

    def initial(self):
        return request(1, "initialize", {"clientInfo": {"name": "factory-evaluator", "version": "0.1"},
                                        "capabilities": {"experimentalApi": self.stage_tool}}, "InitializeParams")

    def interrupt(self):
        self.interrupted = True
        self.outcome = "timeout_incomplete"
        if self.thread and self.turn:
            return request(4, "turn/interrupt", {"threadId": self.thread, "turnId": self.turn}, "TurnInterruptParams")
        return None

    def _identity(self, params, *, turn=True):
        if params.get("threadId") != self.thread:
            raise ValueError("Runtime event belongs to another thread")
        if turn and params.get("turnId") != self.turn:
            raise ValueError("Runtime event belongs to another turn")

    def receive(self, message):
        if not isinstance(message, dict):
            raise ValueError("Runtime message must be an object")
        if "id" in message and "method" not in message:
            identifier = message["id"]
            if identifier in self.responses:
                raise ValueError("Duplicate RPC response")
            if identifier not in (1, 2, 3, 4):
                raise ValueError("Unknown RPC response")
            self.responses.add(identifier)
            if "error" in message:
                self.outcome = "infrastructure_incomplete"
                return []
            result = message.get("result")
            if not isinstance(result, dict):
                raise ValueError("Malformed RPC response")
            if identifier == 1 and self.phase == "initializing":
                params = {"cwd": self.cwd, "model": "gpt-6-luna", "approvalPolicy": "never",
                          "sandbox": "danger-full-access", "allowProviderModelFallback": False,
                          "config": {"features.multi_agent": False, "features.memories": False}}
                if self.stage_tool:
                    params["dynamicTools"] = [{"type": "function", "name": "report_stage",
                        "description": "Report current work stage; stores no readable task state.",
                        "inputSchema": {"type": "object", "additionalProperties": False,
                            "properties": {"stage": {"enum": list(STAGES)}, "wp_id": {"enum": self.packages}},
                            "required": ["stage", "wp_id"]}}]
                self.phase = "starting_thread"
                return [{"method": "initialized"}, request(2, "thread/start", params, "ThreadStartParams")]
            if identifier == 2 and self.phase == "starting_thread":
                self.thread = result["thread"]["id"]
                if not isinstance(self.thread, str) or not self.thread:
                    raise ValueError("Missing thread identity")
                self.phase = "starting_turn"
                return [request(3, "turn/start", {"threadId": self.thread,
                    "input": [{"type": "text", "text": self.prompt}], "model": "gpt-6-luna",
                    "effort": "medium", "approvalPolicy": "never"}, "TurnStartParams")]
            if identifier == 3 and self.phase == "starting_turn":
                returned_turn = result["turn"]["id"]
                if self.turn and self.turn != returned_turn:
                    raise ValueError("Turn response disagrees with started event")
                self.turn = returned_turn
                if not isinstance(self.turn, str) or not self.turn:
                    raise ValueError("Missing turn identity")
                self.phase = "running"
                return []
            if identifier == 4 and self.interrupted:
                return []
            raise ValueError("Out-of-order RPC response")
        method = message.get("method")
        params = message.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            raise ValueError("Malformed runtime notification")
        if "id" in message:
            if method != "item/tool/call" or not self.stage_tool:
                self.outcome = "execution_boundary_incomplete"
                return [{"id": message["id"], "error": {"code": -32601, "message": "Unattended request denied"}}]
            validate("DynamicToolCallParams", params)
            self._identity(params)
            args = params["arguments"]
            valid = (params["tool"] == "report_stage" and params.get("namespace") is None
                     and isinstance(args, dict) and set(args) == {"stage", "wp_id"}
                     and args["stage"] in STAGES and args["wp_id"] in self.packages)
            if not valid:
                self.outcome = "protocol_violation"
            else:
                identity = params["callId"]
                if identity in self.calls and self.calls[identity] != args:
                    raise ValueError("Conflicting duplicate stage call")
                if identity not in self.calls:
                    self.calls[identity] = args
                    self.stage_events.append(dict(args))
            response = {"contentItems": [{"type": "inputText", "text": "Recorded" if valid else "Rejected"}],
                        "success": valid}
            validate("DynamicToolCallResponse", response)
            return [{"id": message["id"], "result": response}]
        if method == "turn/started":
            self._identity(params, turn=False)
            identity = params["turn"]["id"]
            if self.turn and self.turn != identity:
                raise ValueError("Unexpected extra turn")
            self.turn = identity
        elif method == "turn/completed":
            validate("TurnCompletedNotification", params)
            self._identity(params, turn=False)
            if params["turn"]["id"] != self.turn:
                raise ValueError("Unexpected final turn")
            turn = params["turn"]
            code = (turn.get("error") or {}).get("codexErrorInfo")
            if self.outcome is None:
                self.outcome = ("completed" if turn["status"] == "completed" else
                                "quota_incomplete" if code in ("usageLimitExceeded", "sessionBudgetExceeded") else
                                "interrupted_incomplete" if turn["status"] == "interrupted" else "builder_failure")
            self.phase = "finished"
        elif method == "thread/tokenUsage/updated":
            validate("ThreadTokenUsageUpdatedNotification", params)
            self._identity(params)
            total = params["tokenUsage"]["total"]
            if any(value < 0 for value in total.values()):
                raise ValueError("Negative token usage")
            if self.usage and any(total.get(key, -1) < value for key, value in self.usage.items()):
                raise ValueError("Cumulative token usage regressed")
            self.usage = total  # Cumulative snapshot; never sum total with last.
        elif method == "item/completed":
            validate("ItemCompletedNotification", params)
            self._identity(params)
            item = params["item"]
            if item["type"] == "contextCompaction":
                self.compactions.add(item["id"])
            if item["type"].startswith("collabAgent"):
                self.outcome = "protocol_violation"
        return []

    def result(self):
        return {"outcome": self.outcome or "infrastructure_incomplete", "thread_id": self.thread,
                "turn_id": self.turn, "usage_total": self.usage, "usage_semantics": "latest_runtime_cumulative_snapshot",
                "compaction_item_count": len(self.compactions), "compaction_evidence": "runtime_reported",
                "stage_events": self.stage_events, "stage_token_allocation": "unallocated",
                "remote_termination_verified": False}


def run_session(attempt, argv, session, *, cwd, builder_seconds, setup_seconds=60, grace_seconds=60,
                max_stream_bytes=64 * 1024 * 1024):
    """Transport execution requires separately authorized sandbox/launch setup.

    This function always kills its local transport; the caller MUST stop/verify the
    named remote sandbox before capture. It does not change any host policy.
    """
    for name, value in (("builder_seconds", builder_seconds), ("setup_seconds", setup_seconds),
                        ("grace_seconds", grace_seconds), ("max_stream_bytes", max_stream_bytes)):
        positive(value, name)
    process = None
    queued = deque([session.initial()])
    pending = b""
    buffer = b""
    total = 0
    started = time.monotonic()
    wall_started = time.time()
    builder_start = None
    stop_at = None
    try:
        with private_file(attempt.directory / "runtime.stderr.log") as err:
            process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            for stream in (process.stdin, process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while session.phase != "finished":
                    now = time.monotonic()
                    # Wall clock catches suspension not counted by monotonic on some hosts.
                    elapsed = max(now - started, time.time() - wall_started)
                    if abs((time.time() - wall_started) - (now - started)) > 5:
                        session.outcome = "clock_discontinuity_incomplete"
                        break
                    deadline_hit = (builder_start is None and elapsed >= setup_seconds) or (
                        builder_start is not None and now - builder_start >= builder_seconds)
                    if deadline_hit and stop_at is None:
                        interruption = session.interrupt()
                        stop_at = now + grace_seconds
                        if interruption:
                            queued.append(interruption)
                        else:
                            break
                    if stop_at and now >= stop_at:
                        break
                    if session.outcome and not session.interrupted and not queued and not pending:
                        break
                    if not pending and queued:
                        message = queued.popleft()
                        if message.get("method") == "turn/start":
                            builder_start = time.monotonic()
                            attempt.emit("controller", "builder.request", {"thread_id": session.thread})
                        pending = (json.dumps(message, allow_nan=False) + "\n").encode()
                        if len(pending) > 1024 * 1024:
                            raise ValueError("Oversized runtime request")
                    if pending:
                        try:
                            written = os.write(process.stdin.fileno(), pending)
                            pending = pending[written:]
                        except BlockingIOError:
                            pass
                    for key, _ in selector.select(0.02):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(data)
                        if total > max_stream_bytes:
                            raise ValueError("Runtime output limit exceeded")
                        if key.data == "stderr":
                            err.write(data)
                        else:
                            buffer += data
                            if len(buffer) > 1024 * 1024:
                                raise ValueError("Runtime line limit exceeded")
                            while b"\n" in buffer:
                                line, buffer = buffer.split(b"\n", 1)
                                message = json.loads(line)
                                attempt.emit("runtime", "message", message)
                                queued.extend(session.receive(message))
                    if not selector.get_map():
                        if buffer or session.phase != "finished":
                            raise ValueError("Runtime closed without complete final event")
    except Exception as error:
        session.outcome = "infrastructure_incomplete"
        attempt.emit("controller", "runtime.error", {"error_type": type(error).__name__})
    finally:
        if process:
            kill_group(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
    return session.result()
