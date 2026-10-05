"""Protected browser journey execution inside an operator-contained container.

The parent owns container identity, isolation, independent lifetime enforcement,
upstream relay evidence and cleanup. This worker cannot certify those controls.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit

from .browser import BROWSER_MODES
from .evidence import atomic_json, positive
from .grading import contained_file, sha256
from .http_relay import RelayServer
from .verdicts import Inconclusive, Untested


def load_case(root, digest, identifier):
    root = Path(root).resolve(strict=True)
    manifest = contained_file(root, "suite.json")
    if sha256(manifest) != digest:
        raise ValueError("Protected manifest identity changed")
    document = json.loads(manifest.read_text())
    if document.get("schema_version") != 1 or not document.get("files"):
        raise ValueError("Invalid protected manifest")
    for relative, expected in document["files"].items():
        if sha256(contained_file(root, relative)) != expected:
            raise ValueError("Protected source identity changed")
    cases = [case for case in document["cases"] if case["id"] == identifier]
    if len(cases) != 1:
        raise ValueError("Invalid protected case identity")
    case = cases[0]
    if (case.get("browser") not in BROWSER_MODES or case["source"] not in document["files"]
            or not re.fullmatch(r"[a-z][a-z0-9_]*", case["function"])
            or case.get("mutates_runtime", False) or case.get("reads_audit", False)):
        raise ValueError("Invalid protected browser declaration")
    spec = importlib.util.spec_from_file_location("protected_browser", contained_file(root, case["source"]))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return case, module


def invoke(case, module, browser, request_factory, target):
    """Adapt declared signatures; discard journey return data rather than log it."""
    context = None
    result = {"case_id": case["id"], "verdict": "inconclusive"}
    try:
        mode = case["browser"]
        if mode not in BROWSER_MODES:
            raise ValueError("Unknown browser invocation")
        subject = browser
        if mode.startswith("page"):
            context = browser.new_context(viewport={"width": 1280, "height": 800}, accept_downloads=True)
            subject = context.new_page()
            subject.set_default_timeout(target.get("browser_timeout_ms", 10000))
        args = [subject, target]
        if mode.endswith("_request"):
            args.append(request_factory)
        value = getattr(module, case["function"])(*args)
        if value is not None and not isinstance(value, dict):
            raise ValueError("Unexpected browser observation")
        result["verdict"] = "pass"
    except Exception as error:
        # Protected prototypes define these signals locally so they can also
        # run in independent fixture images without importing the controller.
        restoration = getattr(module, "BrowserRestorationError", None)
        unavailable = getattr(module, "BrowserFixtureUnavailable", None)
        if isinstance(restoration, type) and isinstance(error, restoration):
            result.update(reason="browser_restoration_incomplete", abort_suite=True)
        elif isinstance(unavailable, type) and isinstance(error, unavailable):
            result["reason"] = "browser_fixture_unavailable"
        elif isinstance(error, AssertionError):
            result.update(verdict="fail", reason="browser_assertion")
        elif isinstance(error, Untested):
            result.update(verdict="untested", reason="browser_untested")
        elif isinstance(error, Inconclusive):
            result["reason"] = "browser_fixture_unavailable"
        else:
            result["reason"] = "browser_exception"
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                result.update(verdict="inconclusive", reason="browser_context_cleanup", abort_suite=True)
    return result


def isolation_check():
    if os.geteuid() == 0 or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
        raise RuntimeError("Browser requires unprivileged loopback-only containment")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if int(status["CapEff"].strip(), 16) != 0 or status["NoNewPrivs"].strip() != "1":
        raise RuntimeError("Browser process privileges unavailable")


def execute(root, digest, identifier, target, *, socket_path, wall_deadline, playwright_factory=None):
    """Return redacted worker evidence, not a parent guard or cleanup claim.

    Run only with a separate container deadline: Playwright calls and cleanup
    cannot be forcibly bounded here. The Unix socket is operator-mounted readonly.
    """
    result = {"case_id": identifier, "verdict": "inconclusive"}
    relay = thread = browser = None
    try:
        positive(wall_deadline, "browser wall deadline")
        isolation_check()
        origin = urlsplit(target["base_url"])
        if (origin.scheme != "http" or origin.hostname != "127.0.0.1" or not origin.port
                or origin.path or origin.query or origin.fragment or origin.username or origin.password
                or origin.netloc != f"127.0.0.1:{origin.port}"):
            raise ValueError("Browser origin must be the exact operator loopback endpoint")
        if any(name in target for name in ("_audit_control", "_fault_control")):
            raise ValueError("Host capabilities cannot enter the browser worker")
        def check():
            if time.time() >= wall_deadline:
                raise TimeoutError("Browser lifetime expired")
        check()
        case, module = load_case(root, digest, identifier)
        target = dict(target)
        operation_ms = target.get("browser_timeout_ms", 10000)
        positive(operation_ms, "browser operation timeout")
        target["browser_timeout_ms"] = min(operation_ms, max(1, (wall_deadline - time.time()) * 1000))
        relay = RelayServer(("127.0.0.1", origin.port), {"kind": "unix", "path": str(socket_path)},
                            origin.netloc, check=check, request_seconds=min(30, max(.01, wall_deadline - time.time())))
        thread = threading.Thread(target=relay.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        thread.start()
        if playwright_factory is None:
            from playwright.sync_api import sync_playwright
            playwright_factory = sync_playwright
        with playwright_factory() as engine:
            try:
                browser = engine.chromium.launch(headless=True, chromium_sandbox=True)
                result = invoke(case, module, browser, engine.request, target)
                result["browser_version"] = browser.version
                check()
            finally:
                if browser is not None:
                    try:
                        browser.close()
                    except Exception:
                        result.update(verdict="inconclusive", reason="browser_cleanup", abort_suite=True)
                        raise
    except Exception:
        result.update(verdict="inconclusive", reason="browser_worker_incomplete")
    finally:
        if relay is not None:
            try:
                if thread is not None:
                    relay.shutdown()
                    thread.join(2)
                    if thread.is_alive():
                        raise RuntimeError("Browser relay did not stop")
                relay.server_close()
            except Exception:
                result.update(verdict="inconclusive", reason="browser_relay_cleanup", abort_suite=True)
            result["transport"] = relay.observation()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("suite", "manifest-sha256", "case", "target", "socket", "result"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--wall-deadline", type=float, required=True)
    args = parser.parse_args()
    result = execute(args.suite, args.manifest_sha256, args.case, json.loads(Path(args.target).read_text()),
                     socket_path=args.socket, wall_deadline=args.wall_deadline)
    atomic_json(Path(args.result), result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
