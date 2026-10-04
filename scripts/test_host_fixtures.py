#!/usr/bin/env python3
"""Run the fixture suite on Mac in isolated Python 3.11 and 3.14 environments."""

import json
from pathlib import Path
import platform
import signal
import tempfile

from inspect_host import REPO, collect, utc_now


def main():
    if platform.system() != "Darwin":
        raise SystemExit("Run on the host Mac")
    base = REPO / ".factory-planning/host-fixture-logs"
    base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    print(f"Logs: {directory}", flush=True)
    print("Downloads missing Python/dependencies through uv; uses isolated environments, not .venv.", flush=True)
    summary = {"started": utc_now(), "checks": [], "outcome": "running",
               "cleanup": "Fixture temporary repositories are cleaned by unittest; uv caches and logs are retained."}
    commands = [
        ("revision", ["git", "rev-parse", "HEAD"], 30),
        ("status-before", ["git", "status", "--porcelain"], 30),
        ("macos", ["sw_vers"], 30),
        ("uv", ["uv", "--version"], 30),
        ("bash", ["bash", "--version"], 30),
    ]
    for version in ("3.11", "3.14"):
        prefix = ["uv", "run", "--isolated", "--locked", "--python", version, "python"]
        commands.append((f"python-{version}", prefix + ["--version"], 300))
        commands.append((f"tests-{version}", prefix + ["-m", "unittest", "discover", "-s", "tests", "-v"], 300))
    commands.extend([
        ("diff-check", ["git", "diff", "--check"], 30),
        ("status-after", ["git", "status", "--porcelain"], 30),
    ])
    try:
        for label, command, timeout in commands:
            summary["checks"].append(collect(directory, label, command, timeout))
        summary["outcome"] = "passed" if all(item["outcome"] == "ok" for item in summary["checks"]) else "failed"
        before = (directory / "status-before.stdout.log").read_text()
        after = (directory / "status-after.stdout.log").read_text()
        summary["worktree_unchanged"] = before == after
        if before or after:
            summary["outcome"] = "review_required_dirty_worktree"
    except KeyboardInterrupt:
        summary["outcome"] = "interrupted"
    except Exception as error:
        summary.update(outcome="error", error=str(error))
    finally:
        summary["ended"] = utc_now()
        (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Outcome: {summary['outcome']}\nLogs: {directory}", flush=True)
    return 0 if summary["outcome"] == "passed" else 1


if __name__ == "__main__":
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
