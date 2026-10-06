"""Selected immutable source remains captured bytes across guarded fixture work."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.source_binding import SourceBinding
from evaluation.verdicts import Inconclusive


class SourceBindingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        (self.project / 'ops').mkdir(parents=True)
        self.source = self.project / 'ops/bootstrap.sh'
        self.source.write_bytes(b'#!/bin/sh\nexit 0\n')
        self.source.chmod(0o700)
        self.expected = {'ops/bootstrap.sh': dict(sha256=hashlib.sha256(self.source.read_bytes()).hexdigest(),
                                                 size=self.source.stat().st_size, executable=True)}
        self.binding = SourceBinding(self.project, self.expected, lifetime_check=lambda reserve: True)

    def test_expected_selection_is_copied_and_unselected_generated_files_are_outside_scope(self):
        self.expected.clear()
        (self.project / 'ops/fixture-ids.json').write_text('generated fixture configuration')
        self.assertIs(self.binding.check(10), True)

    def test_changed_bytes_size_execute_bit_missing_link_and_special_file_refuse(self):
        initial = self.source.read_bytes()
        for mode in ('same-size', 'size', 'mode', 'missing', 'symlink', 'hardlink', 'fifo'):
            with self.subTest(mode=mode):
                if self.source.exists() or self.source.is_symlink(): self.source.unlink()
                self.source.write_bytes(initial); self.source.chmod(0o700)
                extra = self.root / 'extra'
                if extra.exists(): extra.unlink()
                if mode == 'same-size': self.source.write_bytes(b'x' * len(initial))
                elif mode == 'size': self.source.write_bytes(initial + b'x')
                elif mode == 'mode': self.source.chmod(0o600)
                elif mode == 'missing': self.source.unlink()
                elif mode == 'symlink':
                    extra.write_bytes(initial); self.source.unlink(); self.source.symlink_to(extra)
                elif mode == 'hardlink': os.link(self.source, extra)
                else: self.source.unlink(); os.mkfifo(self.source)
                with self.assertRaises(Inconclusive): self.binding.check()

    def test_root_replacement_refuses_even_identical_source(self):
        self.project.rename(self.root / 'old-project')
        (self.project / 'ops').mkdir(parents=True)
        self.source.write_bytes((self.root / 'old-project/ops/bootstrap.sh').read_bytes())
        self.source.chmod(0o700)
        with self.assertRaises(Inconclusive): self.binding.check()

    def test_root_and_nested_symlink_ancestors_refuse(self):
        (self.project / 'ops').rename(self.root / 'old-ops')
        (self.project / 'ops').symlink_to(self.root / 'old-ops', target_is_directory=True)
        with self.assertRaises(Inconclusive): self.binding.check()
        with self.assertRaises(Inconclusive):
            SourceBinding(self.project, self.expected, lifetime_check=lambda reserve: True)

    def test_root_symlink_refuses_before_read(self):
        self.project.rename(self.root / 'old-project')
        self.project.symlink_to(self.root / 'old-project', target_is_directory=True)
        with self.assertRaises(Inconclusive): self.binding.check()

    def test_path_replacement_during_held_file_read_refuses(self):
        original_read = os.read
        changed = False
        def read(descriptor, count):
            nonlocal changed
            result = original_read(descriptor, count)
            if not changed:
                changed = True
                self.source.rename(self.root / 'old-source')
                self.source.write_bytes((self.root / 'old-source').read_bytes())
                self.source.chmod(0o700)
            return result
        with patch('evaluation.source_binding.os.read', side_effect=read):
            with self.assertRaises(Inconclusive): self.binding.check()

    def test_parent_replacement_during_held_file_read_refuses(self):
        original_read = os.read
        changed = False
        def read(descriptor, count):
            nonlocal changed
            result = original_read(descriptor, count)
            if not changed:
                changed = True
                (self.project / 'ops').rename(self.root / 'old-ops')
                (self.project / 'ops').mkdir()
                self.source.write_bytes((self.root / 'old-ops/bootstrap.sh').read_bytes())
                self.source.chmod(0o700)
            return result
        with patch('evaluation.source_binding.os.read', side_effect=read):
            with self.assertRaises(Inconclusive): self.binding.check()

    def test_nontrue_guard_owner_and_invalid_reserve_refuse(self):
        for result in (False, None, 1, 'true'):
            self.binding.lifetime_check = lambda reserve: result
            with self.assertRaises(Inconclusive): self.binding.check()
        self.binding.lifetime_check = lambda reserve: True
        with patch('evaluation.source_binding.os.getpid', return_value=os.getpid()+1):
            with self.assertRaises(Inconclusive): self.binding.check()
        for reserve in (True, -1, float('nan'), float('inf')):
            with self.assertRaises(ValueError): self.binding.check(reserve)

    def test_invalid_selections_refuse(self):
        record = self.expected['ops/bootstrap.sh']
        for name in ('../outside', '/absolute', 'ops//bootstrap.sh', './ops/bootstrap.sh', '.', 'ops/../bootstrap.sh', 'ops\\bootstrap.sh', 'ops/\nfile'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                SourceBinding(self.project, {name: record}, lifetime_check=lambda reserve: True)
        for changed in (dict(record, size=True), dict(record, executable=1), dict(record, sha256='invalid'), dict(record, kind='symlink'), dict(record, unknown=True)):
            with self.assertRaises(ValueError):
                SourceBinding(self.project, {'ops/bootstrap.sh': changed}, lifetime_check=lambda reserve: True)
        with self.assertRaises(ValueError):
            SourceBinding(self.project, self.expected, lifetime_check=lambda reserve: True, max_bytes=1)


if __name__ == '__main__': unittest.main()
