"""Exercise the published shell recipes with a bounded fake sbx transport."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


README = (Path(__file__).resolve().parents[1] / "README.md").read_text()
BLOCKS = re.findall(r"```sh\n(.*?)\n```", README, re.DOTALL)
RUN_ONCE = next(block for block in BLOCKS if "factory_run_once()" in block)
RUN_LOOP = next(block for block in BLOCKS if "FACTORY_NEXT_TASK=" in block)


class RunRecipeTest(unittest.TestCase):
    def run_recipe(self, recipe, stop_after=1, interrupt=None):
        with tempfile.TemporaryDirectory() as temporary:
            calls = Path(temporary) / "calls"
            pauses = Path(temporary) / "pauses"
            environment = {**os.environ, "CALLS_LOG": str(calls), "PAUSES_LOG": str(pauses),
                           "STOP_AFTER": str(stop_after), "INTERRUPT": interrupt or "",
                           "FACTORY_PROJECT": "/tmp/project with spaces"}
            fake_transport = r'''
factory_call_count=0
sbx() {
  factory_call_count=$((factory_call_count + 1))
  printf '%s\0' "$@" >> "$CALLS_LOG"
  if [ "$factory_call_count" -ge "$STOP_AFTER" ]; then return 7; fi
  return 0
}
sleep() {
  printf '%s\n' "$@" >> "$PAUSES_LOG"
  if [ -n "$INTERRUPT" ]; then kill -s "$INTERRUPT" "$BASHPID"; fi
}
'''
            result = subprocess.run(["bash", "-c", fake_transport + RUN_ONCE + "\n" + recipe],
                                    env=environment, capture_output=True, text=True, timeout=5)
            arguments = calls.read_bytes().decode().split("\0")[:-1] if calls.exists() else []
            delays = pauses.read_text().splitlines() if pauses.exists() else []
        return result, arguments, delays

    def test_one_task_preserves_arguments_and_failure_status(self):
        result, arguments, delays = self.run_recipe("factory_run_once 'one task with spaces'")
        self.assertEqual(result.returncode, 7)
        self.assertEqual(arguments, ["exec", "-w", "/tmp/project with spaces", "my-project-factory",
                                     "codex", "exec", "--cd", "/tmp/project with spaces",
                                     "--dangerously-bypass-approvals-and-sandbox", "one task with spaces"])
        self.assertEqual(delays, [])

    def test_loop_polls_after_success_and_stops_on_first_failure(self):
        result, arguments, delays = self.run_recipe(RUN_LOOP, stop_after=3)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(delays, ["30", "30"])
        self.assertEqual(len(arguments), 30)
        self.assertEqual(arguments[:10], arguments[10:20])
        self.assertEqual(arguments[:10], arguments[20:])
        self.assertIn("Run failed (exit 7)", result.stderr)

    def test_interrupts_stop_without_launching_another_session(self):
        for signum, expected in (("INT", 130), ("TERM", 143)):
            with self.subTest(signal=signum):
                result, arguments, delays = self.run_recipe(RUN_LOOP, stop_after=3, interrupt=signum)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(len(arguments), 10)
                self.assertEqual(delays, ["30"])
