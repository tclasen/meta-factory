"""Source/image mismatches and private transport failures remain distinguishable."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.image_source import inspect_image_archive
from evaluation.image_source_transport import capture_image_source


def archive(content=b'captured source', mode=0o644, *, missing=False, extra=False,
            duplicate=False, name='srv/app/main.py', kind=tarfile.REGTYPE):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as target:
        directory = tarfile.TarInfo('srv');directory.type=tarfile.DIRTYPE
        target.addfile(directory)
        if not missing:
            entry = tarfile.TarInfo(name);entry.mode=mode;entry.type=kind
            if kind == tarfile.REGTYPE:entry.size=len(content)
            if kind == tarfile.SYMTYPE:entry.linkname='/outside'
            target.addfile(entry,io.BytesIO(content) if entry.size else None)
            if duplicate:target.addfile(entry,io.BytesIO(content))
        if extra:
            entry=tarfile.TarInfo('srv/unselected');entry.size=1
            target.addfile(entry,io.BytesIO(b'x'))
    return stream.getvalue()


class ImageSourceTest(unittest.TestCase):
    def setUp(self):
        self.selection={'app/main.py':dict(archive_path='srv/app/main.py',
            sha256=hashlib.sha256(b'captured source').hexdigest(),size=15,executable=False)}
        self.modes={'app/main.py':0o644}

    def inspect(self, raw):return inspect_image_archive(raw,self.selection,self.modes)

    def test_exact_selected_content_and_mode_without_raw_names_or_bytes(self):
        result=self.inspect(archive())
        self.assertEqual(result['outcome'],'image_source_observed')
        self.assertIs(result['selected_source_bytes_match'],True)
        self.assertIs(result['selected_source_modes_match'],True)
        self.assertFalse(result['build_consumption_verified'])
        self.assertFalse(result['deployed_image_verified'])
        text=json.dumps(result)
        self.assertNotIn('app/main.py',text);self.assertNotIn('captured source',text)

    def test_known_byte_mode_and_missing_source_mismatches_are_observed_false(self):
        for raw,bytes_match,modes_match in ((archive(b'changed source!'),False,True),
                                          (archive(mode=0o600),True,False),
                                          (archive(missing=True),False,False)):
            value=self.inspect(raw)
            self.assertEqual(value['outcome'],'image_source_observed')
            self.assertIs(value['selected_source_bytes_match'],bytes_match)
            self.assertIs(value['selected_source_modes_match'],modes_match)

    def test_extra_files_do_not_claim_exhaustive_image_provenance(self):
        value=self.inspect(archive(extra=True))
        self.assertTrue(value['selected_source_bytes_match'])
        self.assertEqual(value['outside_selection_files'],1)
        self.assertEqual(value['archive_files'],2)

    def test_corrupt_truncated_appended_duplicate_or_unsafe_archive_unknown(self):
        raw=archive()
        for value in (b'bad',raw[:1000],raw[:1024],raw+archive(extra=True),
                      archive(duplicate=True),archive(name='../escape'),
                      archive(name='/srv/app/main.py'),archive(name='srv//app/main.py'),
                      archive(kind=tarfile.SYMTYPE),archive(kind=tarfile.LNKTYPE),
                      archive(kind=tarfile.FIFOTYPE)):
            result=self.inspect(value)
            self.assertEqual(result['outcome'],'image_source_incomplete')
            self.assertIsNone(result['selected_source_bytes_match'])

    def test_unsupported_or_unbound_mapping_refused(self):
        for mutation in ('mode','executable','duplicate','path'):
            selection={key:dict(value) for key,value in self.selection.items()};modes=dict(self.modes)
            if mutation=='mode':modes['app/main.py']=0o4644
            if mutation=='executable':selection['app/main.py']['executable']=True
            if mutation=='duplicate':
                selection['other']=dict(selection['app/main.py']);modes['other']=0o644
            if mutation=='path':selection['app/main.py']['archive_path']='../outside'
            with self.assertRaises(ValueError):inspect_image_archive(archive(),selection,modes)

    def test_private_transport_exact_stopped_peer_binding_and_no_extraction(self):
        self.transport(archive(),lambda reserve:True,expected='image_source_observed')

    def test_transport_errors_bounds_and_late_binding_failure_remain_unknown(self):
        self.transport(archive(),lambda reserve:True,expected='image_source_incomplete',exit_code=9)
        self.transport(archive(),lambda reserve:True,expected='image_source_incomplete',bound=1024)
        checks=iter((True,True,False))
        self.transport(archive(),lambda reserve:next(checks),expected='image_source_incomplete')

    def test_transport_timeout_never_claims_source_match_or_remote_termination(self):
        value=self.transport(archive(),lambda reserve:True,expected='image_source_incomplete',
                             delay=1,timeout=.05)
        self.assertFalse(value['remote_termination_verified'])
        self.assertEqual(value['error_type'],'Inconclusive')

    def transport(self, raw, check, *, expected, exit_code=0, bound=64*1024**2,
                  delay=0,timeout=60):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=root/'archive';payload.write_bytes(raw)
            # The trusted fixture simulates Docker cp; supplied application code
            # is never imported or executed, nor is a tar member extracted.
            helper=root/'copy.py'
            helper.write_text('import pathlib,sys,time\n'
                'assert sys.argv[1]=="cp" and sys.argv[2]=="'+('a'*64)+':/srv" and sys.argv[3]=="-"\n'
                'time.sleep('+str(delay)+')\n'
                'sys.stdout.buffer.write(pathlib.Path('+repr(str(payload))+').read_bytes())\n'
                'sys.stderr.write("private diagnostic canary")\n'
                'raise SystemExit('+str(exit_code)+')\n')
            with Attempt(root/'logs',{}) as attempt:
                value=capture_image_source(attempt,docker_prefix=[sys.executable,str(helper)],
                    container_id='a'*64,image_id='sha256:'+'b'*64,image_path='/srv',
                    selection=self.selection,modes=self.modes,check=check,cwd=root,max_archive_bytes=bound,
                    timeout=timeout)
            self.assertEqual(value['outcome'],expected)
            if expected=='image_source_incomplete':
                self.assertIsNone(value['selected_source_bytes_match'])
                self.assertFalse(value['immutable_image_bound'])
            logs=''.join(p.read_text() for p in (root/'logs').rglob('*') if p.is_file())
            self.assertNotIn('private diagnostic canary',logs)
            self.assertNotIn('captured source',logs)
            self.assertFalse((root/'srv').exists())
            return value


if __name__=='__main__':unittest.main()
