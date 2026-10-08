"""Private storage must not alter nonroot build input permissions."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.deployment import verify_capture
from evaluation.sandbox import capture_tree
from evaluation.source_modes import restore_deployment_modes, validate_modes


class SourceModesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/'source'
        (self.source/'app').mkdir(parents=True)
        (self.source/'app/code.py').write_text('source')
        (self.source/'app/code.py').chmod(0o644)
        (self.source/'private.cfg').write_text('private')
        (self.source/'private.cfg').chmod(0o600)
        (self.source/'tool').write_text('executable')
        (self.source/'tool').chmod(0o751)
        (self.source/'empty').mkdir(mode=0o750)
        self.source.chmod(0o755)
        (self.source/'app').chmod(0o755)
        self.capture = self.root/'capture'
        self.inventory = capture_tree(self.source, self.capture, termination_verified=True)

    def stage(self, inventory=None):
        destination = self.root/'stage'
        capture_tree(self.capture, destination, termination_verified=True)
        restore_deployment_modes(destination, inventory or self.inventory, captured_source=self.capture)
        return destination

    def test_storage_stays_private_and_exact_file_directory_modes_roundtrip(self):
        self.assertEqual((self.capture/'app').stat().st_mode&0o777, 0o700)
        self.assertEqual((self.capture/'app/code.py').stat().st_mode&0o777, 0o600)
        destination = self.stage()
        verify_capture(destination, self.inventory)
        for relative in ('.', 'app', 'app/code.py', 'private.cfg', 'tool', 'empty'):
            self.assertEqual((destination/relative).stat().st_mode&0o777,
                             (self.source/relative).stat().st_mode&0o777)
        self.assertEqual((self.capture/'app/code.py').stat().st_mode&0o777, 0o600)
        self.assertEqual((self.capture/'tool').stat().st_mode&0o777, 0o700)

    def test_recapture_private_metadata_does_not_replace_original_provenance(self):
        recaptured = capture_tree(self.capture, self.root/'second', termination_verified=True)
        self.assertEqual(recaptured['files'], self.inventory['files'])
        self.assertEqual(recaptured['unix_modes']['files']['app/code.py'], 0o600)
        self.assertEqual(self.inventory['unix_modes']['files']['app/code.py'], 0o644)

    def test_legacy_incomplete_unbound_and_special_mode_metadata_refused(self):
        for mutate in (lambda record: record.pop('unix_modes'),
                       lambda record: record['unix_modes']['files'].pop('private.cfg'),
                       lambda record: record['unix_modes']['directories'].pop('empty'),
                       lambda record: record['unix_modes'].update(capture_manifest_sha256='0'*64),
                       lambda record: record['unix_modes']['files'].update(tool=0o4751),
                       lambda record: record['unix_modes']['files'].update(tool=0o644),
                       lambda record: record['unix_modes']['files'].update(tool=True)):
            record = copy.deepcopy(self.inventory)
            mutate(record)
            with self.assertRaises(ValueError):
                validate_modes(self.capture, record)

    def test_retained_artifact_public_parent_and_extra_empty_directory_refused(self):
        with self.assertRaises(ValueError):
            restore_deployment_modes(self.capture, self.inventory, captured_source=self.capture)
        (self.capture/'extra').mkdir()
        with self.assertRaises(ValueError):
            validate_modes(self.capture, self.inventory)
        (self.capture/'extra').rmdir()
        destination = self.root/'public'/'stage'
        destination.parent.mkdir(mode=0o755)
        capture_tree(self.capture, destination, termination_verified=True)
        with self.assertRaises(ValueError):
            restore_deployment_modes(destination, self.inventory, captured_source=self.capture)

    def test_directory_metadata_changes_during_capture_are_incomplete(self):
        original_read = os.read
        changed = []
        def mutate(descriptor, count):
            value = original_read(descriptor, count)
            if value and not changed:
                (self.source/'app').chmod(0o750)
                changed.append(True)
            return value
        with patch('evaluation.sandbox.os.read', side_effect=mutate):
            with self.assertRaises(ValueError):
                capture_tree(self.source, self.root/'changed', termination_verified=True)

    def test_relative_links_are_preserved_without_chmod_of_their_targets(self):
        source = self.root/'links'
        source.mkdir()
        (source/'real').write_text('linked')
        (source/'real').chmod(0o640)
        (source/'alias').symlink_to('real')
        captured = self.root/'linked-capture'
        record = capture_tree(source, captured, termination_verified=True)
        destination = self.root/'linked-stage'
        capture_tree(captured, destination, termination_verified=True)
        restore_deployment_modes(destination, record, captured_source=captured)
        self.assertTrue((destination/'alias').is_symlink())
        self.assertNotIn('alias', record['unix_modes']['files'])
        self.assertEqual((destination/'real').stat().st_mode&0o777, 0o640)


if __name__ == '__main__':
    unittest.main()
