"""Copy only reviewed specification bytes into an exclusively owned mount root."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from .evidence import atomic_json, positive, private_file
from .sandbox import disjoint


def read_regular(path, limit, check):
    check()
    # Keep each parent open while opening its child. O_NOFOLLOW on only the
    # final file would still follow a directory replaced with a symlink.
    absolute=Path(os.path.abspath(path))
    parent=os.open(absolute.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for component in absolute.parts[1:-1]:
            check()
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                          dir_fd=parent)
            os.close(parent);parent=child
        check()
        descriptor=os.open(absolute.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
                           dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(descriptor,'rb') as stream:
        metadata=os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_size>limit:
            raise ValueError('Specification requires bounded ordinary unlinked files')
        data=bytearray()
        while True:
            check()
            chunk=stream.read(min(65536,limit-len(data)+1))
            check()
            if not chunk:break
            data.extend(chunk)
            if len(data)>limit:raise ValueError('Specification byte limit exceeded')
    return bytes(data)


def snapshot(root, expected, max_bytes, max_files, check):
    if root.is_symlink() or not root.is_dir():raise ValueError('Specification root must be an ordinary directory')
    data={};total=0
    for path in root.rglob('*'):
        check();metadata=path.lstat()
        if stat.S_ISDIR(metadata.st_mode):continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1:
            raise ValueError('Specification links and special files are forbidden')
        name=str(path.relative_to(root))
        if name not in expected:raise ValueError('Unreviewed specification file')
        if len(data)>=max_files:raise ValueError('Specification file limit exceeded')
        value=read_regular(path,max_bytes-total,check);total+=len(value)
        if hashlib.sha256(value).hexdigest()!=expected[name]:raise ValueError('Reviewed specification bytes changed')
        data[name]=value
    if set(data)!=set(expected):raise ValueError('Reviewed specification files missing')
    return data,total


def write_file(path, data):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(data);stream.flush();os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())


def prepare_specification(attempt, workload, destination, *, monotonic_deadline,
                          wall_deadline, max_bytes=64*1024**2, max_files=256,
                          monotonic=time.monotonic, wall=time.time):
    """One preparation per attempt. Retain owned partial copies; never execute bytes.

    Deadlines are checked around bounded regular-file reads and writes. Filesystem
    I/O itself is not interruptible here; the outer preparation owner must enforce
    its overall deadline and revalidate identities before mounting or launching.
    Receipt success proves a byte copy, not a readonly sbx mount or launch gate.
    """
    for value in (monotonic_deadline,wall_deadline):positive(value,'specification deadline')
    if any(type(value) is not int or value<=0 for value in (max_bytes,max_files)):
        raise ValueError('Positive integer specification limits required')
    workload=Path(workload).resolve(strict=True)
    proposed=Path(destination)
    if proposed.is_symlink():raise ValueError('Destination link forbidden')
    destination=proposed.resolve()
    repository=Path(__file__).resolve().parents[1]
    for protected in (workload,attempt.directory,repository):disjoint(destination,protected)
    owner=os.getpid()
    def check():
        if os.getpid()!=owner or min(monotonic_deadline-monotonic(),wall_deadline-wall())<=0:
            raise TimeoutError('Specification preparation lifetime unavailable')
    with private_file(attempt.directory/'specification-preparation.lock'):
        pass
    report=dict(outcome='specification_preparation_incomplete',destination=str(destination),
                destination_created=False,files={},copied_bytes=0)
    receipt=attempt.directory/'specification-preparation.json'
    try:
        check()
        review=workload/'review'
        if review.is_symlink() or not review.is_dir():raise ValueError('Ordinary workload review directory required')
        approval_path=review/'WORKLOAD-APPROVAL.json'
        approval_bytes=read_regular(approval_path,65536,check)
        def unique_pairs(items):
            result={}
            for key,value in items:
                if key in result:raise ValueError('Duplicate approval key')
                result[key]=value
            return result
        approval=json.loads(approval_bytes,object_pairs_hook=unique_pairs)
        if (not isinstance(approval,dict) or approval.get('schema_version')!=1
                or approval.get('approval_type')!='workload_and_envelope_review_not_suite_freeze'
                or not isinstance(approval.get('workload_sha256'),dict) or not approval['workload_sha256']):
            raise ValueError('Reviewed workload specification record required')
        expected={}
        for name,digest in approval['workload_sha256'].items():
            path=Path(name)
            if (path.is_absolute() or '..' in path.parts or str(path)!=name or len(path.parts)<2
                    or path.parts[0]!='builder' or not isinstance(digest,str)
                    or not re.fullmatch('[0-9a-f]{64}',digest)):
                raise ValueError('Invalid reviewed specification identity')
            expected[str(Path(*path.parts[1:]))]=digest
        data,total=snapshot(workload/'builder',expected,max_bytes,max_files,check)
        destination.mkdir(mode=0o700)
        report['destination_created']=True
        for name,value in sorted(data.items()):
            check();write_file(destination/name,value)
            report['files'][name]=expected[name];report['copied_bytes']+=len(value)
            check()
        snapshot(destination,expected,max_bytes,max_files,check)
        snapshot(workload/'builder',expected,max_bytes,max_files,check)
        if read_regular(approval_path,65536,check)!=approval_bytes:
            raise ValueError('Workload review changed during specification preparation')
        for directory in destination.rglob('*'):
            check()
            if directory.is_dir():directory.chmod(0o555)
        destination.chmod(0o555)
        check()
        report.update(outcome='specification_prepared',copied_bytes=total,
                      approval_sha256=hashlib.sha256(approval_bytes).hexdigest(),
                      limits='Reviewed byte copy only; mount isolation, runtime configuration, suite approval and launch remain separate.')
        atomic_json(receipt,report);check()
        return report
    except BaseException as error:
        report.update(outcome='specification_preparation_incomplete',error_type=type(error).__name__)
        if report['destination_created']:report['retained_destination']=str(destination)
        atomic_json(receipt,report)
        raise
