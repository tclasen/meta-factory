"""Read selected source through a held Linux process root, without executing it.

Run in a trusted operator observer with access to the selected PID namespace.
Caller anchors PID/start ticks to its independent runtime/Pod mapping and bounds
observer lifetime. No environments, command lines or source paths are emitted.
Filesystem/argv identity does not prove loaded modules or process memory.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time


class ProcessSourceUnavailable(ValueError):pass


def identity(value):
    return tuple(getattr(value,key) for key in ('st_dev','st_ino','st_mode','st_size',
                 'st_uid','st_gid','st_nlink','st_mtime_ns','st_ctime_ns'))


def inspect_process_source(pid, start_ticks, executable_sha256, selection, argv, uid, gid,
                           *, proc=Path('/proc')):
    if (type(pid) is not int or not 1 <= pid <= 2147483647
            or not isinstance(start_ticks,str) or not re.fullmatch('[0-9]{1,24}',start_ticks)
            or not isinstance(executable_sha256,str) or not re.fullmatch('[0-9a-f]{64}',executable_sha256)
            or not isinstance(selection,dict) or not 1 <= len(selection) <= 4096
            or not isinstance(argv,list) or not 1 <= len(argv) <= 128
            or any(not isinstance(v,str) or not v or '\x00' in v or len(v)>4096 for v in argv)
            or any(type(v) is not int or not 0 <= v <= 2147483647 for v in (uid,gid))):
        raise ValueError('Bounded independent process/source selection required')
    total = 0
    for name, value in selection.items():
        path = PurePosixPath(name) if isinstance(name,str) else None
        if (path is None or not path.is_absolute() or name=='/' or str(path)!=name
                or '..' in path.parts or '\\' in name or any(ord(c)<32 for c in name)
                or not isinstance(value,dict) or set(value)!={'sha256','size','mode'}
                or not isinstance(value['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['sha256'])
                or type(value['size']) is not int or not 0 <= value['size'] <= 8*1024**2
                or type(value['mode']) is not int or not 0 <= value['mode'] <= 0o777):
            raise ValueError('Canonical selected source and original mode required')
        total += value['size']
    if total > 64*1024**2:raise ValueError('Selected process source bound')
    process = Path(proc)/str(pid)
    started,wall = time.monotonic(),time.time()
    def deadline():
        if max(time.monotonic()-started,time.time()-wall)>35:
            raise ProcessSourceUnavailable('process_source_deadline')
    def read(name,limit):
        deadline()
        with (process/name).open('rb') as stream:value=stream.read(limit+1)
        if len(value)>limit:raise ProcessSourceUnavailable('process_field_bound')
        return value
    def snapshot():
        row=read('stat',8192).decode('ascii');fields=row.rsplit(')',1)[1].split()
        if (row.split(' ',1)[0]!=str(pid) or len(fields)<20 or fields[0] not in ('R','S','D','I')
                or fields[19]!=start_ticks):
            raise ProcessSourceUnavailable('process_identity_changed')
        status=read('status',16384).decode('ascii');identities={}
        for name in ('Uid','Gid'):
            values=[line.split(':',1)[1].split() for line in status.splitlines() if line.startswith(name+':')]
            if len(values)!=1 or len(values[0])!=4 or any(not v.isdigit() for v in values[0]):
                raise ProcessSourceUnavailable('process_credentials_shape')
            identities[name]=[int(v) for v in values[0]]
        command=read('cmdline',65536)
        root=(process/'root').stat()
        namespaces={}
        for name in ('pid','mnt','net'):
            value=(process/'ns'/name).stat();namespaces[name]=(value.st_dev,value.st_ino)
        return dict(identities=identities,cmdline_sha256=hashlib.sha256(command).hexdigest(),
                    argv_match=command==b'\0'.join(v.encode() for v in argv)+b'\0',
                    root=(root.st_dev,root.st_ino),namespaces=namespaces)
    before=snapshot();root=executable=None
    bytes_match=modes_match=True
    source_identities={}
    try:
        # Following these two kernel proc links is intentional. The PID/start
        # witness and repeated root/namespace/executable identities bind them;
        # ordinary source ancestors and leaves below the held root use NOFOLLOW.
        root=os.open(process/'root',os.O_RDONLY|os.O_DIRECTORY)
        held=os.fstat(root)
        if (held.st_dev,held.st_ino)!=before['root']:
            raise ProcessSourceUnavailable('process_root_changed')
        executable=os.open(process/'exe',os.O_RDONLY|os.O_NONBLOCK)
        def digest_file(descriptor,limit):
            first=os.fstat(descriptor)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink!=1 or first.st_size>limit:
                raise ProcessSourceUnavailable('regular_file_required')
            digest=hashlib.sha256();count=0
            while True:
                deadline();chunk=os.read(descriptor,65536)
                if not chunk:break
                count+=len(chunk)
                if count>limit:raise ProcessSourceUnavailable('file_read_bound')
                digest.update(chunk)
            if identity(first)!=identity(os.fstat(descriptor)) or count!=first.st_size:
                raise ProcessSourceUnavailable('selected_file_changed')
            return first,digest.hexdigest(),count
        exe_info,exe_digest,_=digest_file(executable,256*1024**2)
        if identity(exe_info)!=identity((process/'exe').stat()):
            raise ProcessSourceUnavailable('process_executable_changed')
        for name,expected in selection.items():
            parent=os.dup(root);descriptor=None
            try:
                parts=PurePosixPath(name).parts[1:]
                for component in parts[:-1]:
                    child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    os.close(parent);parent=child
                descriptor=os.open(parts[-1],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=parent)
                info,digest,count=digest_file(descriptor,8*1024**2)
                if identity(info)!=identity(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)):
                    raise ProcessSourceUnavailable('selected_name_changed')
                bytes_match &= digest==expected['sha256'] and count==expected['size']
                modes_match &= stat.S_IMODE(info.st_mode)==expected['mode']
                source_identities[name]=identity(info)
            finally:
                if descriptor is not None:os.close(descriptor)
                os.close(parent)
        # Reopen ancestry from the held root, so a renamed parent or a change to
        # an earlier selected file cannot disappear behind an old directory FD.
        for name,expected_identity in source_identities.items():
            deadline();parent=os.dup(root)
            try:
                parts=PurePosixPath(name).parts[1:]
                for component in parts[:-1]:
                    child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    os.close(parent);parent=child
                if identity(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False))!=expected_identity:
                    raise ProcessSourceUnavailable('selected_ancestry_changed')
            finally:os.close(parent)
        if before!=snapshot() or identity(exe_info)!=identity((process/'exe').stat()):
            raise ProcessSourceUnavailable('process_snapshot_changed')
        deadline()
    finally:
        if executable is not None:os.close(executable)
        if root is not None:os.close(root)
    return dict(outcome='process_source_observed',pid=pid,process_start_ticks=start_ticks,
                snapshot_stable=True,selected_files=len(selection),selected_source_bytes_match=bool(bytes_match),
                selected_source_modes_match=bool(modes_match),selected_argv_match=before['argv_match'],
                selected_uid_match=before['identities']['Uid']==[uid]*4,
                selected_gid_match=before['identities']['Gid']==[gid]*4,
                executable_match=exe_digest==executable_sha256,
                process_identity_sha256=hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),
                loaded_modules_verified=False,process_memory_verified=False,pod_attribution_verified=False)


if __name__=='__main__':
    try:
        value=json.loads(sys.stdin.buffer.read(1024*1024+1))
        result=inspect_process_source(**value)
    except Exception as error:
        result=dict(outcome='process_source_incomplete',error_type=type(error).__name__)
    print(json.dumps(result))
