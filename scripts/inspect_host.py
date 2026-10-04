#!/usr/bin/env python3
"""Collect bounded, read-only Mac/sbx diagnostics in the shared checkout."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[1]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def collect(directory, label, command, timeout=30):
    """Preserve output and status, and stop the command group on interruption."""
    record = {"check": label, "command": command, "started": utc_now()}
    start = time.monotonic()
    process = None
    try:
        with (directory / f"{label}.stdout.log").open("wb") as stdout, (
            directory / f"{label}.stderr.log"
        ).open("wb") as stderr:
            process = subprocess.Popen(
                command, cwd=REPO, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True,
            )
            record["exit_code"] = process.wait(timeout=timeout)
            record["outcome"] = "ok" if record["exit_code"] == 0 else "failed"
    except subprocess.TimeoutExpired:
        record.update(outcome="timeout", exit_code=None)
    except OSError as error:
        record.update(outcome="unavailable", exit_code=None, error=str(error))
    except KeyboardInterrupt:
        record.update(outcome="interrupted", exit_code=None)
        raise
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            record["exit_code"] = process.returncode
        record.update(ended=utc_now(), elapsed_seconds=round(time.monotonic() - start, 3))
        (directory / f"{label}.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"{label}: {record['outcome']}", flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox", help="Optional existing sandbox name for effective policy inspection")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("Run this script on the host Mac, not inside sbx")
    base = REPO / ".factory-planning/host-preflight-logs"
    base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    print(f"Logs: {directory}", flush=True)
    print("Read-only inspection; no sandbox creation, policy changes, or model calls.", flush=True)
    summary = {
        "started": utc_now(), "outcome": "running", "checks": [],
        "cleanup": "No test resources created; logs retained.",
        "limitations": "Inspection only; does not establish network enforcement or Kubernetes isolation.",
    }
    commands = [
        ("revision", ["git", "rev-parse", "HEAD"]),
        ("worktree", ["git", "status", "--porcelain"]),
        ("macos", ["sw_vers"]),
        ("architecture", ["uname", "-m"]),
        ("memory", ["sysctl", "-n", "hw.memsize"]),
        ("disk", ["df", "-h", str(REPO)]),
        ("python", [sys.executable, "--version"]),
        ("sbx-version", ["sbx", "version"]),
        ("sbx-help", ["sbx", "--help"]),
        ("create-help", ["sbx", "create", "--help"]),
        ("exec-help", ["sbx", "exec", "--help"]),
        ("sandboxes", ["sbx", "ls"]),
        ("policy-help", ["sbx", "policy", "--help"]),
        ("policy-init-help", ["sbx", "policy", "init", "--help"]),
        ("policy-allow-help", ["sbx", "policy", "allow", "network", "--help"]),
        ("policy-deny-help", ["sbx", "policy", "deny", "network", "--help"]),
        ("policy-check-help", ["sbx", "policy", "check", "network", "--help"]),
        ("policy-list-help", ["sbx", "policy", "ls", "--help"]),
        ("global-policy", ["sbx", "policy", "ls", "--wide"]),
    ]
    if args.sandbox:
        commands.append(("sandbox-policy", ["sbx", "policy", "ls", args.sandbox, "--wide"]))
    try:
        for label, command in commands:
            summary["checks"].append(collect(directory, label, command))
        summary["outcome"] = (
            "collected" if all(item["outcome"] == "ok" for item in summary["checks"])
            else "partial"
        )
    except KeyboardInterrupt:
        summary["outcome"] = "interrupted"
    except Exception as error:
        summary.update(outcome="error", error=str(error))
    finally:
        summary["ended"] = utc_now()
        (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Outcome: {summary['outcome']}\nLogs: {directory}", flush=True)
    return 0 if summary["outcome"] == "collected" else 1


if __name__ == "__main__":
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
