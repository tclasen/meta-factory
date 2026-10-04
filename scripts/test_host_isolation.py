#!/usr/bin/env python3
"""Run a disposable sbx mount, Kubernetes, and network-denial preflight on Mac."""

import json
from pathlib import Path
import platform
import signal
import sys
import tempfile
import uuid

from inspect_host import REPO, collect, utc_now


K3S_IMAGE = "rancher/k3s:v1.34.1-k3s1"
PROBE = """
import json, sys, urllib.request, urllib.error
try:
    with urllib.request.urlopen('https://registry.npmjs.org/', timeout=20) as response:
        status = response.status
except urllib.error.HTTPError as error:
    status = error.code
except Exception as error:
    print(json.dumps({'error_type': type(error).__name__}))
    sys.exit(2)
print(json.dumps({'http_status': status, 'expected': int(sys.argv[1])}))
sys.exit(0 if status == int(sys.argv[1]) else 1)
"""


def main():
    if platform.system() != "Darwin":
        raise SystemExit("Run on the host Mac, not inside sbx")
    base = REPO / ".factory-planning/isolation-preflight-logs"
    base.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    temporary = Path(tempfile.mkdtemp(prefix="factory-isolation-")).resolve()
    workspace = temporary / "workspace"
    workspace.mkdir()
    (workspace / "mounted-canary.txt").write_text("factory mounted canary\n")
    outside = temporary / "outside-canary.txt"
    outside.write_text("factory host-only canary\n")
    sandbox = "factory-isolation-" + uuid.uuid4().hex[:12]
    summary = {
        "started": utc_now(), "outcome": "running", "sandbox": sandbox,
        "workspace": str(workspace), "host_fixture": str(temporary),
        "checks": [], "cleanup": [],
        "manual_cleanup": ["sbx stop " + sandbox, "sbx rm " + sandbox],
        "limitations": [
            "Sampled mount and proxied HTTPS checks, not proof against every escape or egress path.",
            "Wildcard deny is not a validated default-deny policy with usable allowlist exceptions.",
            "Kubernetes uses privileged nested Docker; no protected grader or model is run.",
            "Image tags are recorded with resolved digests; this is feasibility, not a frozen study.",
        ],
    }
    print(f"Logs: {evidence}\nSandbox: {sandbox}\nHost fixture: {temporary}", flush=True)
    print("Creates one 4-CPU/8-GiB sandbox and a nested Kubernetes container; downloads images.", flush=True)
    print("Changes only that sandbox's network policy; stops it afterward and retains evidence.", flush=True)
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    attempted_create = False

    def run(label, command, timeout=60, required=True):
        result = collect(evidence, label, command, timeout)
        summary["checks"].append(result)
        if required and result["outcome"] != "ok":
            raise RuntimeError(f"{label}: {result['outcome']}; inspect its logs")
        return result

    def inside(label, command, timeout=60, required=True):
        return run(label, ["sbx", "exec", sandbox, *command], timeout, required)

    try:
        run("revision", ["git", "rev-parse", "HEAD"])
        run("worktree", ["git", "status", "--porcelain"])
        run("sbx-version", ["sbx", "version"])
        run("profile-help", ["sbx", "policy", "profile", "--help"], required=False)
        attempted_create = True
        run("create", ["sbx", "create", "--name", sandbox, "--cpus", "4",
                       "--memory", "8g", "--skills", "off", "codex", str(workspace)], 300)
        inside("python-version", ["python3", "--version"])
        inside("mount-boundary", ["python3", "-c", """
from pathlib import Path
import json, sys
mounted, outside, evidence = map(Path, sys.argv[1:])
result = {'mounted_readable': mounted.read_text() == 'factory mounted canary\\n',
          'host_canary_visible': outside.exists(), 'evidence_visible': evidence.exists()}
print(json.dumps(result))
sys.exit(0 if result['mounted_readable'] and not result['host_canary_visible'] and not result['evidence_visible'] else 1)
""", str(workspace / "mounted-canary.txt"), str(outside), str(evidence)])
        inside("docker-version", ["docker", "version"])
        inside("network-before", ["python3", "-c", PROBE, "200"])
        inside("k3s-pull", ["docker", "pull", K3S_IMAGE], 300)
        inside("k3s-image", ["docker", "image", "inspect", "--format",
                            "{{json .RepoDigests}}", K3S_IMAGE])
        inside("k3s-start", ["docker", "run", "--detach", "--privileged",
                            "--name", "factory-k3s", K3S_IMAGE, "server",
                            "--disable", "traefik", "--disable", "servicelb",
                            "--disable", "metrics-server"], 120)
        inside("k3s-ready", ["sh", "-c", """
for attempt in $(seq 1 36); do
  if docker exec factory-k3s kubectl wait --for=condition=Ready node --all --timeout=5s; then
    exit 0
  fi
  sleep 5
done
exit 1
"""], 390)
        inside("workload-create", ["docker", "exec", "factory-k3s", "kubectl",
                                   "create", "job", "factory-smoke",
                                   "--image=busybox:1.37.0", "--", "sh", "-c",
                                   "echo factory-kubernetes-ok"])
        inside("workload-complete", ["docker", "exec", "factory-k3s", "kubectl",
                                     "wait", "--for=condition=complete", "job/factory-smoke",
                                     "--timeout=180s"], 200)
        inside("workload-logs", ["docker", "exec", "factory-k3s", "kubectl",
                                 "logs", "job/factory-smoke"])
        inside("workload-image", ["docker", "exec", "factory-k3s", "kubectl", "get", "pods",
                                  "-l", "job-name=factory-smoke", "-o",
                                  "jsonpath={.items[*].status.containerStatuses[*].imageID}"])
        run("deny-egress", ["sbx", "policy", "deny", "network", "--sandbox", sandbox, "**"])
        run("effective-policy", ["sbx", "policy", "ls", sandbox, "--wide"])
        run("policy-registry", ["sbx", "policy", "check", "network", "--sandbox", sandbox,
                                "--json", "registry.npmjs.org:443"], required=False)
        run("policy-unlisted", ["sbx", "policy", "check", "network", "--sandbox", sandbox,
                                "--json", "example.com:443"], required=False)
        inside("network-denied", ["python3", "-c", PROBE, "403"])
        summary["outcome"] = "checks_passed_pending_log_review"
    except KeyboardInterrupt:
        summary["outcome"] = "interrupted"
    except Exception as error:
        summary.update(outcome="blocked_or_failed", error=str(error))
    finally:
        if attempted_create:
            # Logs can contain cluster credentials; collect Kubernetes events, not server logs.
            summary["cleanup"].append(collect(evidence, "cluster-events", [
                "sbx", "exec", sandbox, "docker", "exec", "factory-k3s",
                "kubectl", "get", "events", "--all-namespaces",
            ], 30))
            summary["cleanup"].append(collect(evidence, "cluster-remove", [
                "sbx", "exec", sandbox, "docker", "rm", "--force", "--volumes", "factory-k3s",
            ], 30))
            summary["cleanup"].append(collect(evidence, "sandbox-stop", ["sbx", "stop", sandbox], 60))
        summary["ended"] = utc_now()
        summary["cleanup_ok"] = all(item["outcome"] == "ok" for item in summary["cleanup"])
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Outcome: {summary['outcome']}\nLogs: {evidence}", flush=True)
        print(f"Cleanup checks passed: {summary['cleanup_ok']}. Host fixture retained.", flush=True)
        print(f"If stopping failed, run: sbx stop {sandbox}", flush=True)
    return 0 if summary["outcome"] == "checks_passed_pending_log_review" and all(
        item["outcome"] == "ok" for item in summary["cleanup"]
    ) else 1


if __name__ == "__main__":
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
