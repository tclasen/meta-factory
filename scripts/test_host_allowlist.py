#!/usr/bin/env python3
"""Opt-in, temporary global allow-all removal with logged restoration."""

import argparse
import fcntl
import json
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from inspect_host import REPO, collect, utc_now
from test_host_isolation import K3S_IMAGE, PROBE


RESTORE = ["sbx", "policy", "allow", "network", "--protocol", "tcp", "**"]
K3S_PIN = "rancher/k3s@sha256:5e0707cfd1239b358ef73f3254bc3eadc027dd30cd5ec6ca41e29e47652a1b8c"
BUSYBOX_PIN = "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
DOCKER_DESTINATIONS = (
    "registry-1.docker.io:443", "auth.docker.io:443",
    "production.cloudflare.docker.com:443", "production.cloudfront.docker.com:443",
)


def global_allow_rule(snapshot):
    rules = [rule for rule in snapshot["rules"] if rule.get("scope") == "global"]
    if len(rules) != 1:
        raise ValueError("Expected exactly one global network rule; no policy changes made")
    rule = rules[0]
    if not (rule.get("decision") == "allow" and rule.get("resources") == ["**"]
            and rule.get("actions") == ["net:connect:tcp"] and rule.get("editable") is True
            and rule.get("status") == "active" and rule.get("policy_id") == "local-policy"):
        raise ValueError("Global policy differs from the reviewed TCP allow-all baseline")
    return rule["id"]


def restore(directory, label):
    with (directory / "restore.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        marker = directory / "restoration-needed"
        if not marker.exists():
            return True
        # A failed removal may have left the original rule intact; avoid duplicates.
        inspection = collect(directory, label + "-inspect", [
            "sbx", "policy", "ls", "--type", "network", "--json",
        ], 30)
        if inspection["outcome"] == "ok":
            try:
                global_allow_rule(json.loads((directory / (label + "-inspect.stdout.log")).read_text()))
            except (ValueError, KeyError, OSError):
                pass
            else:
                marker.unlink()
                return True
        result = collect(directory, label, RESTORE, 30)
        if result["outcome"] == "ok":
            marker.unlink()
            return True
        return False


def watchdog(directory):
    # Independent process survives an interrupted/killed parent; no credentials needed.
    time.sleep(240)
    return 0 if restore(directory, "watchdog-restore") else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-temporary-global-policy-change", action="store_true")
    parser.add_argument("--pods", action="store_true", help="Include paired sandbox and Kubernetes pod probes")
    parser.add_argument("--builder-toolchain", action="store_true",
                        help="Pull pinned images and run a nested k3s job during default deny")
    parser.add_argument("--watchdog", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if platform.system() != "Darwin":
        parser.error("Run on the host Mac")
    if args.watchdog:
        return watchdog(args.watchdog)
    if not args.allow_temporary_global_policy_change:
        parser.error("Explicit --allow-temporary-global-policy-change is required; affects all sandboxes")
    base = REPO / ".factory-planning/allowlist-preflight-logs"
    base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    sandbox = "factory-allowlist-" + uuid.uuid4().hex[:12]
    summary = {"started": utc_now(), "sandbox": sandbox, "outcome": "running",
               "checks": [], "cleanup": [], "restored": False, "pods": args.pods,
               "builder_toolchain": args.builder_toolchain,
               "builder_images": [K3S_PIN, BUSYBOX_PIN] if args.builder_toolchain else [],
               "builder_destinations": list(DOCKER_DESTINATIONS) if args.builder_toolchain else [],
               "manual_restore": "sbx policy allow network --protocol tcp '**'",
               "limitations": "Restores TCP allow-all behavior, not the original rule ID/provenance. Sampled egress only."}
    print(f"Logs: {directory}\nSandbox: {sandbox}", flush=True)
    print("Temporarily removes GLOBAL TCP allow-all; other sandboxes may lose unlisted egress.", flush=True)
    print("Restores equivalent TCP allow-all afterward, with a new rule ID. No policy reset.", flush=True)
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    attempted_create = False

    def run(label, command, timeout=30, required=True):
        result = collect(directory, label, command, timeout)
        summary["checks"].append(result)
        if required and result["outcome"] != "ok":
            raise RuntimeError(f"{label}: {result['outcome']}")

    def request(label, url, expected):
        code = PROBE.replace("https://registry.npmjs.org/", url)
        run(label, ["sbx", "exec", sandbox, "python3", "-c", code, str(expected)], 30)

    def inside(label, command, timeout=60):
        run(label, ["sbx", "exec", sandbox, *command], timeout)

    def paired(stage):
        source = (Path(__file__).resolve().parent / "egress_probe.py").read_text()
        for destination in ("registry.npmjs.org", "example.com"):
            code = source.replace("registry.npmjs.org", destination)
            label = destination.split(".")[0] + "-" + stage
            inside("sandbox-" + label, ["python3", "-c", code])
            inside("pod-" + label, ["docker", "exec", "factory-k3s", "kubectl", "exec",
                                   "factory-egress", "--", "python3", "-c", code])

    try:
        run("revision", ["git", "rev-parse", "HEAD"])
        run("worktree", ["git", "status", "--porcelain"])
        run("version", ["sbx", "version"])
        run("policy-before", ["sbx", "policy", "ls", "--type", "network", "--json"])
        rule_id = global_allow_rule(json.loads((directory / "policy-before.stdout.log").read_text()))
        attempted_create = True
        run("create", ["sbx", "create", "--name", sandbox,
                       "--cpus", "8" if args.builder_toolchain else ("4" if args.pods else "2"),
                       "--memory", "16g" if args.builder_toolchain else ("8g" if args.pods else "2g"),
                       "--skills", "off", "codex"], 300)
        if args.builder_toolchain:
            for index, destination in enumerate(DOCKER_DESTINATIONS):
                run(f"allow-docker-{index:02d}", ["sbx", "policy", "allow", "network",
                                                   "--sandbox", sandbox, destination])
        request("allowed-baseline", "https://registry.npmjs.org/", 200)
        request("unlisted-baseline", "https://example.com/", 200)
        if args.pods:
            inside("k3s-start", ["docker", "run", "--detach", "--privileged", "--name", "factory-k3s",
                                "--entrypoint", "/bin/sh", K3S_IMAGE, "-ec",
                                'test -e /dev/kmsg || mknod /dev/kmsg c 1 11; exec /bin/k3s "$@"',
                                "factory-k3s", "server", "--disable", "traefik",
                                "--disable", "servicelb", "--disable", "metrics-server"], 300)
            inside("cluster-ready", ["sh", "-c", """
for attempt in $(seq 1 36); do
  [ "$(docker inspect --format '{{.State.Running}}' factory-k3s)" = true ] || exit 1
  if docker exec factory-k3s kubectl wait --for=condition=Ready node --all --timeout=5s &&
     docker exec factory-k3s kubectl get serviceaccount default; then exit 0; fi
  sleep 5
done
exit 1
"""], 390)
            inside("pod-create", ["docker", "exec", "factory-k3s", "kubectl", "run", "factory-egress",
                                  "--image=python:3.14-alpine", "--restart=Never", "--overrides",
                                  json.dumps({"spec": {"dnsConfig": {"options": [{"name": "ndots", "value": "1"}]}}}),
                                  "--command", "--", "sleep", "1200"])
            inside("pod-ready", ["docker", "exec", "factory-k3s", "kubectl", "wait",
                                 "--for=condition=Ready", "pod/factory-egress", "--timeout=180s"], 200)
            inside("k3s-image", ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", K3S_IMAGE])
            inside("pod-image", ["docker", "exec", "factory-k3s", "kubectl", "get", "pod", "factory-egress",
                                 "-o", "jsonpath={.status.containerStatuses[*].imageID}"])
            paired("baseline")
        # Refuse intervening global edits before arming restoration.
        run("policy-recheck", ["sbx", "policy", "ls", "--type", "network", "--json"])
        if global_allow_rule(json.loads((directory / "policy-recheck.stdout.log").read_text())) != rule_id:
            raise RuntimeError("Global policy changed during setup")
        with (directory / "watchdog.log").open("wb") as log:
            subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--watchdog", str(directory)],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        (directory / "restoration-needed").write_text(utc_now())
        run("remove-global-allow", ["sbx", "policy", "rm", "network", "--id", rule_id, "--force"])
        run("policy-during", ["sbx", "policy", "ls", sandbox, "--type", "network", "--json"])
        for label, target in (("allowed-decision", "registry.npmjs.org:443"), ("unlisted-decision", "example.com:443")):
            run(label, ["sbx", "policy", "check", "network", "--sandbox", sandbox, "--json", target], required=False)
        request("allowed-during", "https://registry.npmjs.org/", 200)
        request("unlisted-during", "https://example.com/", 403)
        if args.builder_toolchain:
            inside("builder-k3s-pull", ["docker", "pull", K3S_PIN], 600)
            inside("builder-busybox-pull", ["docker", "pull", BUSYBOX_PIN], 300)
            inside("builder-k3s-start", ["docker", "run", "--detach", "--privileged",
                                         "--name", "factory-k3s", "--entrypoint", "/bin/sh", K3S_PIN,
                                         "-ec", 'test -e /dev/kmsg || mknod /dev/kmsg c 1 11; exec /bin/k3s "$@"',
                                         "factory-k3s", "server", "--disable", "traefik",
                                         "--disable", "servicelb", "--disable", "metrics-server"], 300)
            inside("builder-cluster-ready", ["sh", "-c", """
for attempt in $(seq 1 36); do
  [ "$(docker inspect --format '{{.State.Running}}' factory-k3s)" = true ] || exit 1
  if docker exec factory-k3s kubectl wait --for=condition=Ready node --all --timeout=5s; then exit 0; fi
  sleep 5
done
exit 1
"""], 390)
            inside("builder-kubectl", ["docker", "exec", "factory-k3s", "kubectl", "version", "--client"])
            inside("builder-job-create", ["docker", "exec", "factory-k3s", "kubectl", "create", "job",
                                          "factory-builder-smoke", "--image=" + BUSYBOX_PIN, "--",
                                          "sh", "-c", "echo factory-builder-toolchain-ok"])
            inside("builder-job-complete", ["docker", "exec", "factory-k3s", "kubectl", "wait",
                                            "--for=condition=complete", "job/factory-builder-smoke",
                                            "--timeout=180s"], 200)
            inside("builder-job-logs", ["docker", "exec", "factory-k3s", "kubectl", "logs",
                                        "job/factory-builder-smoke"])
        if args.pods:
            paired("restricted")
        if not (directory / "restoration-needed").exists():
            raise RuntimeError("Watchdog restored policy during observations; attempt is inconclusive")
        summary["outcome"] = "checks_passed_pending_review"
        if args.pods:
            summary["outcome"] = "observations_collected_pending_review"
    except KeyboardInterrupt:
        summary["outcome"] = "interrupted"
    except Exception as error:
        summary.update(outcome="blocked_or_failed", error=str(error))
    finally:
        summary["restored"] = restore(directory, "restore-global-allow")
        if attempted_create:
            if args.pods or args.builder_toolchain:
                summary["cleanup"].append(collect(directory, "cluster-remove", [
                    "sbx", "exec", sandbox, "docker", "rm", "--force", "--volumes", "factory-k3s",
                ], 30))
            summary["cleanup"].append(collect(directory, "sandbox-stop", ["sbx", "stop", sandbox], 60))
        summary["cleanup"].append(collect(directory, "policy-after", ["sbx", "policy", "ls", "--type", "network", "--json"], 30))
        try:
            global_allow_rule(json.loads((directory / "policy-after.stdout.log").read_text()))
        except (ValueError, KeyError, OSError) as error:
            summary.update(restored=False, restoration_verification_error=str(error))
        summary["ended"] = utc_now()
        (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Outcome: {summary['outcome']}\nRestored: {summary['restored']}\nLogs: {directory}", flush=True)
        if not summary["restored"]:
            print("RESTORATION FAILED. Run: " + summary["manual_restore"], flush=True)
    return 0 if summary["outcome"] in (
        "checks_passed_pending_review", "observations_collected_pending_review",
    ) and summary["restored"] and all(
        item["outcome"] == "ok" for item in summary["cleanup"]
    ) else 1


if __name__ == "__main__":
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
