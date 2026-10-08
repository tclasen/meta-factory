"""Expose the reviewed /spec path only inside an owned builder sandbox."""
import json
import os
from pathlib import Path, PurePosixPath
import re

from .evidence import atomic_json, collect


PROBE = '''import hashlib,json,os,stat,sys
from pathlib import Path
try:
 target=Path(sys.argv[1]);expected=json.loads(sys.argv[2]);alias=Path('/spec')
 if not target.is_absolute() or target.resolve(strict=True)!=target or not target.is_dir():raise ValueError()
 created=False
 if os.path.lexists(alias):
  if not alias.is_symlink() or os.readlink(alias)!=str(target):raise ValueError()
 else:
  os.symlink(str(target),alias,target_is_directory=True);created=True
 if alias.resolve(strict=True)!=target:raise ValueError()
 total=0
 for name,digest in expected.items():
  parts=Path(name).parts;current=alias
  for part in parts:
   current=current/part
   if current.is_symlink():raise ValueError()
  before=current.stat()
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>64*1024**2:raise ValueError()
  total+=before.st_size
  if total>64*1024**2:raise ValueError()
  if hashlib.sha256(current.read_bytes()).hexdigest()!=digest:raise ValueError()
  after=current.stat()
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError()
  try:
   descriptor=os.open(current,os.O_WRONLY|os.O_APPEND)
  except OSError as error:
   if error.errno not in (13,30):raise
  else:
   os.close(descriptor);raise ValueError()
 if not alias.is_symlink() or os.readlink(alias)!=str(target):raise ValueError()
 print(json.dumps(dict(outcome='specification_alias_verified',alias='/spec',target=str(target),files=len(expected),alias_created=created,hashes_verified=True,write_denied=True)))
except Exception as error:
 print(json.dumps(dict(outcome='specification_alias_incomplete',error_type=type(error).__name__)))
 sys.exit(1)
'''


def install_specification_alias(attempt, sandbox, expected_files, *, lifetime_check,
                                command_runner=collect):
    """Bounded guest-only provisioning; never run sudo or create /spec on the host.

    Expected hashes come from the independently reviewed workload. An existing
    unrelated /spec is refused, not overwritten. Hash and write-denial probes
    run as guest root, so even elevated guest access must respect the readonly
    mount. The caller owns the watchdog, absolute deadline and sandbox cleanup.
    No model call, prompt modification, suite freeze or launch approval occurs.
    """
    if (not isinstance(expected_files, dict) or not 1 <= len(expected_files) <= 256
            or not callable(lifetime_check) or not callable(command_runner)):
        raise ValueError('Independent bounded specification binding required')
    expected = dict(expected_files)
    for name, digest in expected.items():
        if (not isinstance(name, str) or not name or '\\' in name
                or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                or str(PurePosixPath(name)) != name or name == '.'
                or any(ord(value) < 32 for value in name)
                or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise ValueError('Canonical reviewed specification file hashes required')
    owner = os.getpid()
    scope = (sandbox.name, str(sandbox.project), str(sandbox.specification))
    if (not re.fullmatch('factory-eval-builder-[0-9a-f]{16}', scope[0])
            or not Path(scope[2]).is_absolute() or scope[2] == '/spec'):
        raise ValueError('Owned builder and mounted specification required')
    def live(reserve):
        if (os.getpid() != owner or (sandbox.name, str(sandbox.project), str(sandbox.specification)) != scope
                or sandbox.stopped or sandbox.creation_attempted is not True
                or lifetime_check(reserve) is not True):
            raise ValueError('Specification alias lifetime unavailable')
    report = dict(outcome='specification_alias_incomplete', alias='/spec')
    try:
        live(31)
        tail = ['sudo', '-n', 'python3', '-c', PROBE, scope[2], json.dumps(expected, sort_keys=True)]
        argv = sandbox.exec_argv(tail)
        if argv != ['sbx', 'exec', '-w', scope[1], scope[0], *tail]:
            raise ValueError('Specification alias command escaped its owned sandbox')
        command = command_runner(attempt, 'specification-alias', argv,
            cwd=Path(__file__).resolve().parents[1], timeout=30)
        report['command_outcome'] = command.get('outcome')
        report['command_exit_code'] = command.get('exit_code')
        live(0)
        value = json.loads((attempt.directory/'specification-alias/stdout.log').read_text())
        if (command.get('outcome') == 'passed' and type(command.get('exit_code')) is int
                and command['exit_code'] == 0 and value.get('outcome') == 'specification_alias_verified'
                and value.get('alias') == '/spec' and value.get('target') == scope[2]
                and type(value.get('files')) is int and value['files'] == len(expected)
                and value.get('hashes_verified') is True and value.get('write_denied') is True
                and type(value.get('alias_created')) is bool):
            report.update(outcome='specification_alias_verified', files=len(expected),
                          alias_created=value['alias_created'], hashes_verified=True, write_denied=True)
        live(0)
    except Exception as error:
        report.update(outcome='specification_alias_incomplete', error_type=type(error).__name__)
    finally:
        atomic_json(attempt.directory/'specification-alias-result.json', report)
    return report
