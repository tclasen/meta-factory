"""Guest-only provisioning and revocation of the reviewed specification alias."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from evaluation.specification_alias import PROBE, install_specification_alias


class SpecificationAliasTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.attempt = SimpleNamespace(directory=Path(self.temp.name))
        self.sandbox = SimpleNamespace(name='factory-eval-builder-'+'a'*16,
            project=Path('/private/tmp/project'), specification=Path('/private/tmp/spec'),
            stopped=False, creation_attempted=True)
        self.sandbox.exec_argv = lambda tail: ['sbx','exec','-w',str(self.sandbox.project),self.sandbox.name,*tail]
        self.calls = []
        self.value = dict(outcome='specification_alias_verified', alias='/spec',
            target=str(self.sandbox.specification),files=1,alias_created=True,
            hashes_verified=True,write_denied=True)
        self.status = dict(outcome='passed',exit_code=0)

    def runner(self, attempt, label, argv, **kwargs):
        self.calls.append((argv,kwargs))
        directory = attempt.directory/label
        directory.mkdir()
        (directory/'stdout.log').write_text(json.dumps(self.value))
        return self.status

    def run_probe(self, guard=lambda reserve: True):
        return install_specification_alias(self.attempt,self.sandbox,{'packages.json':'a'*64},
            lifetime_check=guard,command_runner=self.runner)

    def test_exact_guest_command_and_reviewed_hash(self):
        self.assertEqual(self.run_probe()['outcome'],'specification_alias_verified')
        argv,kwargs = self.calls[0]
        self.assertEqual(argv[:8],['sbx','exec','-w','/private/tmp/project',self.sandbox.name,'sudo','-n','python3'])
        self.assertEqual(argv[-2],'/private/tmp/spec')
        self.assertEqual(json.loads(argv[-1]),{'packages.json':'a'*64})
        self.assertEqual(kwargs['timeout'],30)
        compile(PROBE,'guest-probe','exec')

    def test_existing_correct_alias_is_idempotent(self):
        self.value['alias_created'] = False
        self.assertFalse(self.run_probe()['alias_created'])

    def test_failed_command_retains_original_status(self):
        self.status = dict(outcome='failed',exit_code=17)
        result = self.run_probe()
        self.assertEqual(result['outcome'],'specification_alias_incomplete')
        self.assertEqual(result['command_exit_code'],17)

    def test_lost_guard_after_command_preserves_status(self):
        reserves = []
        def guard(reserve):
            reserves.append(reserve)
            return len(reserves)==1
        result = self.run_probe(guard)
        self.assertEqual(result['outcome'],'specification_alias_incomplete')
        self.assertEqual(result['command_exit_code'],0)

    def test_lost_guard_before_command_has_no_side_effect(self):
        self.assertEqual(self.run_probe(lambda reserve: False)['outcome'],'specification_alias_incomplete')
        self.assertEqual(self.calls,[])

    def test_host_command_is_refused(self):
        self.sandbox.exec_argv = lambda tail: tail
        self.assertEqual(self.run_probe()['outcome'],'specification_alias_incomplete')
        self.assertEqual(self.calls,[])

    def test_wrong_binding_and_weak_write_proof_are_refused(self):
        for field,value in [('target','/wrong'),('write_denied',False),('files',True)]:
            with self.subTest(field=field):
                saved = dict(self.value)
                self.value[field] = value
                self.assertEqual(self.run_probe()['outcome'],'specification_alias_incomplete')
                self.value = saved
                (self.attempt.directory/'specification-alias/stdout.log').unlink()
                (self.attempt.directory/'specification-alias').rmdir()

    def test_noncanonical_input_refused_before_provisioning(self):
        for name in ('../private','/absolute','a//b','a/./b'):
            with self.assertRaises(ValueError):
                install_specification_alias(self.attempt,self.sandbox,{name:'a'*64},
                    lifetime_check=lambda reserve: True,command_runner=self.runner)
        self.assertEqual(self.calls,[])
