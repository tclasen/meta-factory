"""Execute one independently hashed, operator-trusted test in a bounded process."""

import argparse
import importlib.util
import json
from pathlib import Path

from .evidence import atomic_json
from .faults import FaultRestoreError, FaultSetupError
from .grading import contained_file, sha256


class Inconclusive(Exception):
    """The required test precondition could not be established."""


class Untested(Exception):
    """No observation procedure was executed for this criterion."""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("suite", "case", "target", "result", "manifest-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    root = Path(args.suite).resolve(strict=True)
    manifest_path = root / "suite.json"
    if sha256(manifest_path) != args.manifest_sha256:
        raise ValueError("Suite manifest changed before execution")
    manifest = json.loads(manifest_path.read_text())
    for relative, expected in manifest["files"].items():
        if sha256(contained_file(root, relative)) != expected:
            raise ValueError("Suite source changed before execution")
    case = next(case for case in manifest["cases"] if case["id"] == args.case)
    source = contained_file(root, case["source"])
    spec = importlib.util.spec_from_file_location("protected_case", source)
    module = importlib.util.module_from_spec(spec)
    result = {"case_id": args.case, "verdict": "inconclusive"}
    try:
        spec.loader.exec_module(module)
        target = json.loads(Path(args.target).read_text())
        value = getattr(module, case["function"])(target)
        if value is not None:
            raise ValueError("Test functions must assert observations and return None")
        result["verdict"] = "pass"
    except FaultRestoreError:
        result.update(verdict="inconclusive", reason="workload_restoration_incomplete", abort_suite=True)
    except FaultSetupError:
        result.update(verdict="inconclusive", reason="workload_fault_precondition_incomplete")
    except AssertionError as error:
        result.update(verdict="fail", reason=str(error)[:2000])
    except Untested as error:
        result.update(verdict="untested", reason=str(error)[:2000])
    except Inconclusive as error:
        result.update(verdict="inconclusive", reason=str(error)[:2000])
    except Exception as error:
        result.update(verdict="inconclusive", reason="grader_exception:" + type(error).__name__)
    atomic_json(Path(args.result), result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
