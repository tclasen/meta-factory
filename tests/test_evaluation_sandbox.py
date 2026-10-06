"""Resource boundaries and untrusted-source capture fixtures."""

import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.evidence import Attempt
from evaluation.sandbox import Sandbox, capture_tree, disjoint, listing_rows, stopped_from_listing


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()

    def capture(self, **kwargs):
        return capture_tree(self.project, self.root / "capture", termination_verified=True, **kwargs)

    def test_mount_ancestor_overlap_rejected(self):
        with self.assertRaises(ValueError):
            disjoint(self.project, self.project / "evidence")

    def test_no_capture_before_remote_stop(self):
        with self.assertRaises(ValueError):
            capture_tree(self.project, self.root / "capture", termination_verified=False)
        self.assertFalse((self.root / "capture").exists())

    def test_capture_hashes_and_preserves_executable_without_running(self):
        script = self.project / "danger.sh"
        script.write_text("#!/bin/sh\nexit 9\n")
        script.chmod(0o755)
        result = self.capture()
        self.assertEqual(result["outcome"], "captured")
        self.assertTrue(result["files"]["danger.sh"]["executable"])
        self.assertEqual((self.root / "capture/danger.sh").read_bytes(), script.read_bytes())

    def test_symlink_escape_rejected_without_reading(self):
        (self.root / "secret").write_text("private")
        (self.project / "escape").symlink_to(self.root / "secret")
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse((self.root / "capture/escape").exists())

    def test_hardlinks_and_size_limit_rejected(self):
        (self.project / "file").write_text("12345")
        with self.assertRaises(ValueError):
            self.capture(max_bytes=4)
        os.link(self.project / "file", self.project / "link")
        with self.assertRaises(ValueError):
            capture_tree(self.project, self.root / "second", termination_verified=True)

    def test_mode_and_hardlink_changes_at_open_are_capture_incomplete(self):
        for mode in ('permissions', 'hardlink'):
            with self.subTest(mode=mode):
                source = self.project / mode; source.write_text('bytes'); source.chmod(0o600)
                original_open = os.open
                def mutate_at_open(path, flags, *args, **kwargs):
                    if Path(path) == source:
                        if mode == 'permissions': source.chmod(0o700)
                        else: os.link(source, self.root / 'external-alias')
                    return original_open(path, flags, *args, **kwargs)
                with patch('evaluation.sandbox.os.open', side_effect=mutate_at_open):
                    with self.assertRaises(ValueError):
                        capture_tree(self.project, self.root / ('capture-' + mode), termination_verified=True)
                source.unlink()

    def test_permission_change_during_read_is_capture_incomplete(self):
        source = self.project / 'file'; source.write_text('bytes'); source.chmod(0o600)
        original_read = os.read
        changed = []
        def mutate_after_read(descriptor, amount):
            data = original_read(descriptor, amount)
            if data and not changed:
                source.chmod(0o700); changed.append(True)
            return data
        with patch('evaluation.sandbox.os.read', side_effect=mutate_after_read):
            with self.assertRaises(ValueError): self.capture()
        self.assertEqual(changed, [True])

    def test_rewrite_with_restored_modification_time_is_capture_incomplete(self):
        source = self.project / 'file'; source.write_text('first')
        before = source.stat(); original_read = os.read; changed = []
        def rewrite_after_read(descriptor, amount):
            data = original_read(descriptor, amount)
            if data and not changed:
                source.write_text('other')
                os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
                changed.append(True)
            return data
        with patch('evaluation.sandbox.os.read', side_effect=rewrite_after_read):
            with self.assertRaises(ValueError): self.capture()
        self.assertEqual(changed, [True])
        self.assertEqual(source.stat().st_mtime_ns, before.st_mtime_ns)

    def test_fifo_swap_at_open_cannot_block_capture(self):
        # Run this race in a bounded child: a regression must not hang unittest.
        program = """import os,sys
from pathlib import Path
from unittest.mock import patch
from evaluation.sandbox import capture_tree
root=Path(sys.argv[1]);source=root/'project'/'file';source.write_text('bytes')
original=os.open
changed=[]
def swap(path,flags,*args,**kwargs):
    if Path(path)==source and not changed:
        source.unlink();os.mkfifo(source);changed.append(True)
    return original(path,flags,*args,**kwargs)
with patch('evaluation.sandbox.os.open',side_effect=swap):
    try:capture_tree(root/'project',root/'capture',termination_verified=True)
    except ValueError:pass
    else:raise AssertionError('FIFO accepted')
assert changed
"""
        result = subprocess.run([sys.executable, '-c', program, str(self.root)],
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_exact_stopped_identity_required(self):
        text = "SANDBOX AGENT STATUS PORTS WORKSPACE\nother codex stopped\nours codex running\n"
        self.assertFalse(stopped_from_listing(text, "ours"))
        self.assertTrue(stopped_from_listing(text.replace("ours codex running", "ours codex stopped"), "ours"))
        self.assertFalse(stopped_from_listing(text, "missing"))
        self.assertFalse(stopped_from_listing("unknown format", "ours"))

    def test_internal_file_and_directory_links_preserved_without_traversal(self):
        (self.project / 'assets').mkdir()
        (self.project / 'assets/file').write_text('content')
        (self.project / 'alias').symlink_to('assets/file')
        (self.project / 'directory-alias').symlink_to('assets', target_is_directory=True)
        result = self.capture()
        self.assertEqual(set(result['files']), {'assets/file', 'alias', 'directory-alias'})
        self.assertEqual(result['files']['alias']['kind'], 'symlink')
        self.assertTrue((self.root / 'capture/directory-alias').is_symlink())
        self.assertEqual(os.readlink(self.root / 'capture/alias'), 'assets/file')

    def test_lexical_escape_via_external_alias_back_into_source_is_rejected(self):
        (self.project / 'file').write_text('content')
        (self.root / 'external').symlink_to(self.project, target_is_directory=True)
        (self.project / 'alias').symlink_to('../external/file')
        with self.assertRaises(ValueError): self.capture()

    def test_scoped_create_plan_and_no_exec_after_stop(self):
        spec = self.root / "spec"; spec.mkdir()
        control = self.root / "control"; control.mkdir()
        with Attempt(control / "logs", {}) as attempt:
            box = Sandbox(attempt, self.project, spec, control, port=18080)
            argv = box.create_argv()
            self.assertIn("127.0.0.1:18080:8080", argv)
            self.assertIn(str(spec) + ":ro", argv)
            self.assertNotIn("--cloud", argv)
            self.assertIn("-i", box.exec_argv(["codex", "app-server"], interactive=True))
            scratch = self.root / 'scratch'; scratch.mkdir()
            with self.assertRaises(ValueError):
                Sandbox(attempt, self.project, spec, control, port=18081,
                        role="grader", project_readonly=True)
            inspector = Sandbox(attempt, self.project, spec, control, port=18081,
                                role="grader", project_readonly=True, primary_workspace=scratch)
            self.assertIn(str(self.project) + ":ro", inspector.create_argv())
            self.assertEqual(inspector.create_argv()[-3:],
                             [str(scratch), str(self.project) + ":ro", str(spec) + ":ro"])
            with self.assertRaises(ValueError):
                box.stop()
            box.stopped = True
            with self.assertRaises(ValueError):
                box.exec_argv(["true"])

    def test_inspected_name_must_match_role_and_owned_format(self):
        spec=self.root/'spec';spec.mkdir();control=self.root/'control';control.mkdir()
        with Attempt(control/'logs',{}) as attempt:
            for name in ('',True,'unrelated','factory-eval-grader-0123456789abcdef',
                         'factory-eval-builder-0123456789abcdeF','factory-eval-builder-1234'):
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        Sandbox(attempt,self.project,spec,control,port=18080,planned_name=name)

    def test_absent_inspected_name_checked_before_exact_creation(self):
        spec=self.root/'spec';spec.mkdir();control=self.root/'control';control.mkdir()
        name='factory-eval-builder-0123456789abcdef'
        with Attempt(control/'logs',{}) as attempt:
            box=Sandbox(attempt,self.project,spec,control,port=18080,planned_name=name)
            commands=[]
            def collect(owner,label,argv,**kwargs):
                commands.append(argv)
                if argv==['sbx','ls']:
                    folder=owner.directory/label;folder.mkdir()
                    (folder/'stdout.log').write_text('SANDBOX AGENT STATUS PORTS WORKSPACE\nunrelated shell stopped - /tmp/other\n')
                return dict(outcome='passed',exit_code=0)
            with patch('evaluation.sandbox.collect',side_effect=collect):
                self.assertEqual(box.create()['outcome'],'passed')
            self.assertEqual(commands,[['sbx','ls'],box.create_argv()])
            self.assertTrue(box.creation_attempted)
            with self.assertRaises(ValueError):box.create()

    def test_present_or_unknown_listing_never_claims_or_stops_named_resource(self):
        spec=self.root/'spec';spec.mkdir();control=self.root/'control';control.mkdir()
        name='factory-eval-builder-0123456789abcdef'
        header='SANDBOX AGENT STATUS PORTS WORKSPACE\n'
        cases=[('running',header+name+' codex running - /tmp/project\n','passed',0),
               ('stopped',header+name+' codex stopped - /tmp/project\n','passed',0),
               ('failed',header,'failed',1),('boolean-exit',header,'passed',False),
               ('unknown','NAME STATUS\n','passed',0),('malformed',header+'unparsed\n','passed',0),
               ('duplicate',header+'other shell stopped\nother shell stopped\n','passed',0)]
        for label,output,outcome,status in cases:
            with self.subTest(label=label):
                with Attempt(control/label,{}) as attempt:
                    box=Sandbox(attempt,self.project,spec,control,port=18080,planned_name=name)
                    calls=[]
                    def collect(owner,check,argv,**kwargs):
                        calls.append(argv);folder=owner.directory/check;folder.mkdir()
                        (folder/'stdout.log').write_text(output)
                        return dict(outcome=outcome,exit_code=status)
                    with patch('evaluation.sandbox.collect',side_effect=collect):
                        with self.assertRaises(ValueError):box.create()
                        with self.assertRaises(ValueError):box.create()
                        with self.assertRaises(ValueError):box.stop()
                    self.assertEqual(calls,[['sbx','ls']])
                    self.assertFalse(box.creation_attempted)
                    self.assertFalse((attempt.directory/'builder-resource.json').exists())


class ListingNoticeTest(unittest.TestCase):
    def listing(self):
        return ('SANDBOX AGENT STATUS PORTS WORKSPACE\nours shell stopped - /tmp/owned\n\n'
            '╭────────╮\n│ Docker Sandboxes Update Available │\n├────────┤\n'
            '│ v0.46.0  →  v0.47.0 │\n├────────┤\n'
            '│ Release notes  https://github.com/docker/sbx-releases/releases/tag/v0.47.0 │\n'
            '├────────┤\n│ To upgrade     brew upgrade docker/tap/sbx │\n╰────────╯\n')

    def test_recognized_notice_preserves_present_and_absent_resource_identities(self):
        from evaluation.recovery import state_from_listing
        value=self.listing()
        self.assertEqual(listing_rows(value),[['ours','shell','stopped','-','/tmp/owned']])
        self.assertTrue(stopped_from_listing(value,'ours'))
        self.assertFalse(stopped_from_listing(value,'missing'))
        self.assertEqual(state_from_listing(value,'ours'),'stopped')
        self.assertEqual(state_from_listing(value,'missing'),'absent')

    def test_unknown_truncated_or_injected_notice_never_establishes_absence_or_stop(self):
        from evaluation.recovery import state_from_listing
        value=self.listing()
        for corrupted in (value.replace('v0.47.0 │','v0.48.0 │',1),
                value.replace('Docker Sandboxes Update Available','Other notice'),
                value.replace('https://github.com/docker/','https://untrusted.invalid/'),
                value.replace('╰────────╯',''),value+'hidden shell running\n',
                value.replace('│ To upgrade','hidden shell running\n│ To upgrade'),
                value.replace('ours shell stopped','ours shell stopped\nours shell stopped')):
            with self.subTest(corrupted=corrupted):
                with self.assertRaises(ValueError):listing_rows(corrupted)
                with self.assertRaises(ValueError):state_from_listing(corrupted,'missing')
                self.assertFalse(stopped_from_listing(corrupted,'ours'))
