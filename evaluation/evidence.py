"""REQ-015/020: exclusive attempts, durable transitions and bounded commands."""

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time
import uuid


TRANSITIONS = {
    "created": {"preflight", "failed"}, "preflight": {"ready", "failed"},
    "ready": {"running", "failed"}, "running": {"stopping", "failed"},
    "stopping": {"captured", "failed"}, "captured": {"grading", "failed"},
    "grading": {"finalized", "failed"}, "failed": {"finalized"}, "finalized": set(),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def positive(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and positive")


def atomic_json(path, value):
    """Replace a private snapshot only after a complete flushed write."""
    data = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def private_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")


class Attempt:
    def __init__(self, directory, manifest, *, max_event_bytes=64 * 1024 * 1024):
        positive(max_event_bytes, "max_event_bytes")
        self.directory = Path(directory)
        # Atomic mkdir is the ownership lock. Never reopen/resume an old attempt.
        self.directory.mkdir(mode=0o700)
        self.id = str(uuid.uuid4())
        self.started = time.monotonic()
        self.sequence = 0
        self.phase = "created"
        self.event_bytes = 0
        self.max_event_bytes = max_event_bytes
        self.events = private_file(self.directory / "events.jsonl")
        try:
            atomic_json(self.directory / "manifest.json", {"schema_version": 1, "attempt_id": self.id,
                                                         "started": utc_now(), "inputs": manifest})
            self.emit("controller", "attempt.created", {})
            self._status()
        except BaseException:
            self.events.close()
            raise

    def close(self):
        self.events.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _status(self):
        atomic_json(self.directory / "status.json", {"attempt_id": self.id, "phase": self.phase,
                                                    "sequence": self.sequence, "updated": utc_now()})

    def emit(self, source, kind, payload):
        if source not in {"controller", "runtime", "grader"}:
            raise ValueError("Unknown evidence source")
        event = {"schema_version": 1, "attempt_id": self.id, "sequence": self.sequence + 1,
                 "utc": utc_now(), "elapsed_seconds": time.monotonic() - self.started,
                 "source": source, "type": kind, "payload": payload}
        encoded = (json.dumps(event, allow_nan=False) + "\n").encode()
        if len(encoded) > 1024 * 1024 or self.event_bytes + len(encoded) > self.max_event_bytes:
            raise ValueError("Evidence size limit exceeded")
        self.events.write(encoded)
        self.events.flush()
        os.fsync(self.events.fileno())
        self.event_bytes += len(encoded)
        self.sequence += 1

    def transition(self, phase):
        if phase not in TRANSITIONS[self.phase]:
            raise ValueError(f"Illegal transition {self.phase} -> {phase}")
        self.emit("controller", "phase.changed", {"from": self.phase, "to": phase})
        self.phase = phase
        self._status()

    def finish(self, result):
        if "finalized" not in TRANSITIONS[self.phase]:
            raise ValueError("Only graded or failed attempts may finalize")
        atomic_json(self.directory / "result.json", result)
        self.transition("finalized")


def kill_group(process):
    # Descendants may still hold pipes after their parent exits.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # On the Mac an exited, unreaped group leader can yield EPERM. Reap our
        # child, then signal again so surviving descendants are still handled.
        # A live leader or a second denial remains a genuine cleanup failure.
        if process.poll() is None:
            raise
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=5)


def collect(attempt, label, argv, *, cwd, timeout, max_output_bytes=16 * 1024 * 1024):
    """No shell, retries or env dump; bound both elapsed time and combined output.

    argv must not contain credentials. Killing this process group does not establish
    termination of remote sbx processes; the sandbox adapter must verify that.
    """
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label):
        raise ValueError("Invalid command label")
    positive(timeout, "timeout")
    positive(max_output_bytes, "max_output_bytes")
    if not argv or not all(isinstance(arg, str) for arg in argv):
        raise ValueError("argv must contain strings")
    check_dir = attempt.directory / label
    check_dir.mkdir(mode=0o700)
    record = {"check": label, "argv": argv, "started": utc_now(), "outcome": "error",
              "exit_code": None, "output_bytes": 0, "remote_termination_verified": False}
    attempt.emit("controller", "command.start", {"check": label, "argv": argv})
    start = time.monotonic()
    process = None
    try:
        with private_file(check_dir / "stdout.log") as out, private_file(check_dir / "stderr.log") as err:
            process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                for stream, destination in ((process.stdout, out), (process.stderr, err)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, destination)
                while selector.get_map() or process.poll() is None:
                    remaining = timeout - (time.monotonic() - start)
                    if remaining <= 0:
                        record["outcome"] = "timeout"
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        available = max_output_bytes - record["output_bytes"]
                        key.data.write(data[:available])
                        record["output_bytes"] += min(len(data), available)
                        if len(data) > available:
                            record["outcome"] = "output_limit"
                            break
                    if record["outcome"] == "output_limit":
                        break
                else:
                    record["outcome"] = "passed" if process.returncode == 0 else "failed"
    except BaseException as error:
        record["outcome"] = "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "error"
        record["error_type"] = type(error).__name__
        if not isinstance(error, Exception):
            raise
    finally:
        cleanup_interrupt = None
        if process is not None:
            def cleanup_failed(error):
                nonlocal cleanup_interrupt
                record.setdefault("command_outcome", record["outcome"])
                record.update(outcome="cleanup_error", cleanup_error_type=type(error).__name__)
                if not isinstance(error, Exception):
                    cleanup_interrupt = error
            try:
                kill_group(process)
            except BaseException as error:
                cleanup_failed(error)
            record["exit_code"] = process.returncode
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except BaseException as error:
                    cleanup_failed(error)
        record.update(ended=utc_now(), elapsed_seconds=time.monotonic() - start)
        atomic_json(check_dir / "result.json", record)
        attempt.emit("controller", "command.end", record)
        if cleanup_interrupt is not None:
            raise cleanup_interrupt
    return record
