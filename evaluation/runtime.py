"""Pinned Codex 0.160.0 single-thread/turn adapter. No model launch CLI."""

from collections import deque
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import time

from jsonschema import Draft7Validator

from .evidence import atomic_json, kill_group, positive, private_file


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


def _runtime_timing(started, requested, observed_end, cleaned_end, interrupted=None):
    """Nonoverlapping local intervals; the interruption grace is a builder subset."""
    samples = dict(transport_start=started, turn_request=requested,
                   observation_stop=observed_end, local_cleanup_end=cleaned_end,
                   interruption_request=interrupted)
    present = [value for value in (started, requested, interrupted, observed_end, cleaned_end)
               if value is not None]
    valid = all(all(math.isfinite(part) for part in value) for value in present)
    if valid:
        valid = (all(before[0] <= after[0] and before[1] <= after[1]
                     for before, after in zip(present, present[1:]))
                 and all(abs((value[0] - started[0]) - (value[1] - started[1])) <= 5
                         for value in present))
    boundaries = {name: None if value is None else dict(
        monotonic_seconds=value[0] if math.isfinite(value[0]) else None,
        utc_epoch_seconds=value[1] if math.isfinite(value[1]) else None)
        for name, value in samples.items()}
    return dict(clock_evidence='monotonic_with_wall_crosscheck' if valid else 'clock_discontinuity',
        boundaries=boundaries,
        setup_elapsed_seconds=(requested or observed_end)[0] - started[0] if valid else None,
        builder_elapsed_seconds=observed_end[0] - requested[0] if valid and requested else None,
        local_cleanup_elapsed_seconds=cleaned_end[0] - observed_end[0] if valid else None,
        transport_elapsed_seconds=cleaned_end[0] - started[0] if valid else None,
        interruption_grace_elapsed_seconds=(observed_end[0] - interrupted[0] if interrupted else 0) if valid else None,
        semantics='Builder interval begins when turn/start is queued for writing and ends when local observation stops. It includes native state work, service delays and interruption grace. Local cleanup is separate; remote stop is not established.')


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
    stream_bytes = {"stdout": 0, "stderr": 0}
    failure_location = "transport_start"
    failure = None
    started = time.monotonic()
    wall_started = time.time()
    builder_start = None
    builder_wall_start = None
    interruption_started = None
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
                            interruption_started = (now, time.time())
                            queued.append(interruption)
                        else:
                            break
                    if stop_at and now >= stop_at:
                        break
                    if session.outcome and not session.interrupted and not queued and not pending:
                        break
                    if not pending and queued:
                        failure_location = "request_encoding"
                        message = queued.popleft()
                        if message.get("method") == "turn/start":
                            builder_start = time.monotonic()
                            builder_wall_start = time.time()
                            attempt.emit("controller", "builder.request", {"thread_id": session.thread})
                        pending = (json.dumps(message, allow_nan=False) + "\n").encode()
                        if len(pending) > 1024 * 1024:
                            failure_location = "request_size_limit"
                            raise ValueError("Oversized runtime request")
                    if pending:
                        failure_location = "request_write"
                        try:
                            written = os.write(process.stdin.fileno(), pending)
                            pending = pending[written:]
                        except BlockingIOError:
                            pass
                    failure_location = "stream_select"
                    for key, _ in selector.select(0.02):
                        failure_location = "stream_read"
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(data)
                        stream_bytes[key.data] += len(data)
                        if total > max_stream_bytes:
                            failure_location = "stream_size_limit"
                            raise ValueError("Runtime output limit exceeded")
                        if key.data == "stderr":
                            failure_location = "stderr_recording"
                            err.write(data)
                        else:
                            buffer += data
                            if len(buffer) > 1024 * 1024:
                                failure_location = "line_size_limit"
                                raise ValueError("Runtime line limit exceeded")
                            while b"\n" in buffer:
                                line, buffer = buffer.split(b"\n", 1)
                                failure_location = "message_decoding"
                                message = json.loads(line)
                                failure_location = "message_recording"
                                attempt.emit("runtime", "message", message)
                                failure_location = "message_processing"
                                queued.extend(session.receive(message))
                    if not selector.get_map():
                        if buffer or session.phase != "finished":
                            failure_location = "premature_stream_close"
                            raise ValueError("Runtime closed without complete final event")
    except Exception as error:
        session.outcome = "infrastructure_incomplete"
        # Fixed locations and numeric counters identify transport failures without
        # copying exception messages, runtime payloads, commands or credentials.
        failure = dict(error_type=type(error).__name__, location=failure_location,
                       stream_bytes=dict(stream_bytes), buffered_stdout_bytes=len(buffer),
                       stream_limit_bytes=max_stream_bytes)
        attempt.emit("controller", "runtime.error", failure)
    finally:
        observation_stop = (time.monotonic(), time.time())
        cleanup_outcome = 'incomplete' if process else 'not_started'
        try:
            if process:
                kill_group(process)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
                cleanup_outcome = 'settled'
        finally:
            requested = None if builder_start is None else (builder_start, builder_wall_start)
            timing = _runtime_timing((started, wall_started), requested, observation_stop,
                                     (time.monotonic(), time.time()), interruption_started)
            timing['local_cleanup_outcome'] = cleanup_outcome
            atomic_json(attempt.directory / 'runtime-timing.json', timing)
            attempt.emit('controller', 'runtime.timing', timing)
            if timing['clock_evidence'] == 'clock_discontinuity':
                session.outcome = 'clock_discontinuity_incomplete'
    result = session.result()
    result['timing'] = timing
    result['runtime_failure'] = failure
    return result
