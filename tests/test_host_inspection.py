import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "inspect_host", Path(__file__).resolve().parents[1] / "scripts/inspect_host.py",
)
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


class HostInspectionTest(unittest.TestCase):
    def test_failure_preserves_output_and_exit_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = HOST.collect(directory, "failure", [
                sys.executable, "-c",
                "import sys; print('output'); print('error', file=sys.stderr); sys.exit(7)",
            ])
            self.assertEqual(result["exit_code"], 7)
            self.assertEqual(result["outcome"], "failed")
            self.assertEqual((directory / "failure.stdout.log").read_text(), "output\n")
            self.assertEqual((directory / "failure.stderr.log").read_text(), "error\n")
            self.assertEqual(json.loads((directory / "failure.json").read_text()), result)

    def test_hanging_command_is_stopped_and_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = HOST.collect(Path(temporary), "timeout", [
                sys.executable, "-c", "import time; time.sleep(60)",
            ], timeout=0.1)
            self.assertEqual(result["outcome"], "timeout")
            self.assertLess(result["exit_code"], 0)
            self.assertLess(result["elapsed_seconds"], 5)

    def test_missing_command_is_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = HOST.collect(Path(temporary), "missing", [
                str(Path(temporary) / "does-not-exist"),
            ])
            self.assertEqual(result["outcome"], "unavailable")
            self.assertIsNone(result["exit_code"])
