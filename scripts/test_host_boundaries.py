#!/usr/bin/env python3
"""Test read-only inputs and host-to-Kubernetes HTTP access with disposable canaries."""

import json
from pathlib import Path
import platform
import signal
import socket
import sys
import tempfile
import uuid

from inspect_host import REPO, collect, utc_now
from test_host_isolation import K3S_IMAGE


SERVICE = {"apiVersion": "v1", "kind": "List", "items": [
    {"apiVersion": "v1", "kind": "Pod", "metadata": {
        "name": "factory-http", "labels": {"app": "factory-http"}},
     "spec": {"dnsConfig": {"options": [{"name": "ndots", "value": "1"}]},
              "containers": [{"name": "http", "image": "python:3.14-alpine",
                              "command": ["sh", "-ec", "mkdir -p /tmp/site; printf 'factory-service-ok\\n' > /tmp/site/index.html; exec python3 -m http.server 8080 --directory /tmp/site"],
                              "readinessProbe": {"httpGet": {"path": "/", "port": 8080}, "periodSeconds": 1}}]}},
    {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "factory-http"},
     "spec": {"type": "NodePort", "selector": {"app": "factory-http"},
              "ports": [{"port": 8080, "targetPort": 8080, "nodePort": 30080}]}}
]}

READ_ONLY = """
from pathlib import Path
import json, sys
path = Path(sys.argv[1])
assert path.read_text() == 'factory-spec-canary\\n'
try:
    path.write_text('modified\\n')
except OSError as error:
    print(json.dumps({'write_rejected': True, 'errno': error.errno}))
    sys.exit(0 if error.errno in (13, 30) else 2)
print(json.dumps({'write_rejected': False}))
sys.exit(1)
"""

HTTP_CHECK = """
import json, sys, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(sys.argv[1], timeout=10) as response:
    body = response.read(1024)
    result = {'status': response.status, 'body_matches': body == b'factory-service-ok\\n'}
print(json.dumps(result))
sys.exit(0 if result['status'] == 200 and result['body_matches'] else 1)
"""


def main():
    if platform.system() != "Darwin":
        raise SystemExit("Run on the host Mac")
    base = REPO / ".factory-planning/boundary-preflight-logs"
    base.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    fixture = Path(tempfile.mkdtemp(prefix="factory-boundary-")).resolve()
    workspace, spec = fixture / "workspace", fixture / "spec"
    workspace.mkdir()
    spec.mkdir()
    canary = spec / "requirement.txt"
    canary.write_text("factory-spec-canary\n")
    (workspace / "service.json").write_text(json.dumps(SERVICE))
    (evidence / "private-canary.txt").write_text("not a real holdout\n")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    sandbox = "factory-boundary-" + uuid.uuid4().hex[:12]
    summary = {"started": utc_now(), "sandbox": sandbox, "host_port": port,
               "fixture": str(fixture), "checks": [], "cleanup": [], "outcome": "running",
               "limits": "Synthetic service and canaries; no authoritative grader, holdout suite, or adversarial escape proof."}
    print(f"Logs: {evidence}\nSandbox: {sandbox}\nHost fixture: {fixture}", flush=True)
    print(f"Publishes synthetic HTTP only at 127.0.0.1:{port}; no network policy changes.", flush=True)
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    attempted = False

    def run(label, command, timeout=60, required=True):
        result = collect(evidence, label, command, timeout)
        summary["checks"].append(result)
        if required and result["outcome"] != "ok":
            raise RuntimeError(f"{label}: {result['outcome']}")

    def inside(label, command, timeout=60, required=True):
        run(label, ["sbx", "exec", sandbox, *command], timeout, required)

    try:
        run("revision", ["git", "rev-parse", "HEAD"])
        run("worktree", ["git", "status", "--porcelain"])
        run("version", ["sbx", "version"])
        attempted = True
        run("create", ["sbx", "create", "--name", sandbox, "--cpus", "4", "--memory", "8g",
                       "--skills", "off", "--publish", f"127.0.0.1:{port}:18080",
                       "codex", str(workspace), str(spec) + ":ro"], 300)
        inside("spec-write-user", ["python3", "-c", READ_ONLY, str(canary)], required=False)
        run("spec-write-root", ["sbx", "exec", "--user", "root", sandbox,
                                "python3", "-c", READ_ONLY, str(canary)], required=False)
        inside("evidence-hidden", ["python3", "-c",
                                   "from pathlib import Path; import sys; visible=Path(sys.argv[1]).exists(); print({'visible':visible}); sys.exit(int(visible))",
                                   str(evidence)], required=False)
        inside("k3s-start", ["docker", "run", "--detach", "--privileged", "--name", "factory-k3s",
                             "-p", "18080:30080", "--entrypoint", "/bin/sh", K3S_IMAGE,
                             "-ec", 'test -e /dev/kmsg || mknod /dev/kmsg c 1 11; exec /bin/k3s "$@"',
                             "factory-k3s", "server", "--disable", "traefik", "--disable", "servicelb",
                             "--disable", "metrics-server"], 300)
        inside("cluster-ready", ["sh", "-c", """
for attempt in $(seq 1 36); do
  [ "$(docker inspect --format '{{.State.Running}}' factory-k3s)" = true ] || exit 1
  if docker exec factory-k3s kubectl wait --for=condition=Ready node --all --timeout=5s &&
     docker exec factory-k3s kubectl get serviceaccount default; then exit 0; fi
  sleep 5
done
exit 1
"""], 390)
        inside("fixture-copy", ["docker", "cp", str(workspace / "service.json"), "factory-k3s:/tmp/service.json"])
        inside("service-create", ["docker", "exec", "factory-k3s", "kubectl", "apply", "-f", "/tmp/service.json"])
        inside("service-ready", ["docker", "exec", "factory-k3s", "kubectl", "wait",
                                 "--for=condition=Ready", "pod/factory-http", "--timeout=180s"], 200)
        inside("service-dns", ["docker", "exec", "factory-k3s", "kubectl", "exec", "factory-http",
                               "--", "python3", "-c", HTTP_CHECK,
                               "http://factory-http.default.svc.cluster.local:8080/"], required=False)
        run("host-http", [sys.executable, "-c", HTTP_CHECK, f"http://127.0.0.1:{port}/"], required=False)
        inside("pod-image", ["docker", "exec", "factory-k3s", "kubectl", "get", "pod", "factory-http",
                             "-o", "jsonpath={.status.containerStatuses[*].imageID}"])
        summary["outcome"] = "observations_collected_pending_review"
    except KeyboardInterrupt:
        summary["outcome"] = "interrupted"
    except Exception as error:
        summary.update(outcome="blocked_or_failed", error=str(error))
    finally:
        summary["spec_unchanged"] = canary.read_text() == "factory-spec-canary\n"
        if attempted:
            summary["cleanup"].append(collect(evidence, "cluster-remove", [
                "sbx", "exec", sandbox, "docker", "rm", "--force", "--volumes", "factory-k3s"], 30))
            summary["cleanup"].append(collect(evidence, "sandbox-stop", ["sbx", "stop", sandbox], 60))
        summary["ended"] = utc_now()
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Outcome: {summary['outcome']}\nLogs: {evidence}\nManual stop: sbx stop {sandbox}", flush=True)
    return 0 if summary["outcome"] == "observations_collected_pending_review" and summary["spec_unchanged"] and all(
        check["outcome"] == "ok" for check in summary["checks"] + summary["cleanup"]
    ) else 1


if __name__ == "__main__":
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
