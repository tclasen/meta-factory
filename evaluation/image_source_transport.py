"""Bounded, private Docker cp transport from an exact stopped image probe."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import subprocess
import time

from .evidence import atomic_json, kill_group, utc_now
from .image_source import inspect_image_archive, selection_records
from .verdicts import Inconclusive


def capture_image_source(attempt, *, docker_prefix, container_id, image_id, image_path,
                         selection, modes, check, cwd, label='image-source', timeout=60,
                         max_archive_bytes=64*1024**2):
    """Read files from a caller-created stopped container; never start it.

    check(reserve) must bind this exact full container ID, immutable image ID,
    never-started state, pristine writable layer, captured selection/modes and
    active outer sandbox lifetime before/after/final. Caller owns the probe's
    creation/removal and interrupts hanging callbacks. Timeouts cannot claim
    remote command termination.
    """
    selection_records(selection, modes)
    path = PurePosixPath(image_path) if isinstance(image_path, str) else None
    if (not isinstance(docker_prefix, (list, tuple)) or not 1 <= len(docker_prefix) <= 24
            or any(not isinstance(v, str) or not v or '\x00' in v or len(v) > 4096 for v in docker_prefix)
            or not isinstance(container_id, str) or not re.fullmatch('[0-9a-f]{64}', container_id)
            or not isinstance(image_id, str) or not re.fullmatch('sha256:[0-9a-f]{64}', image_id)
            or path is None or not path.is_absolute() or str(path) != image_path
            or image_path == '/' or '..' in path.parts or ':' in image_path
            or any(ord(c) < 32 for c in image_path) or not callable(check)
            or not isinstance(label, str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}', label)
            or type(timeout) not in (int,float) or not 0 < timeout <= 60
            or type(max_archive_bytes) is not int or not 1024 <= max_archive_bytes <= 64*1024**2):
        raise ValueError('Exact immutable stopped image probe and bounds required')
    directory = attempt.directory/label
    directory.mkdir(mode=0o700)
    record = dict(started=utc_now(), outcome='image_source_incomplete', exit_code=None,
                  stdout_bytes=0, stderr_bytes=0, immutable_image_bound=False,
                  selected_source_bytes_match=None, selected_source_modes_match=None,
                  remote_termination_verified=False, image_id=image_id,
                  container_identity_sha256=hashlib.sha256(container_id.encode()).hexdigest())
    attempt.emit('controller','image.source.started',dict(record,label=label))
    process = None
    try:
        if check(timeout+5) is not True:raise Inconclusive('Image probe binding unavailable')
        started = time.monotonic()
        process = subprocess.Popen([*docker_prefix,'cp',container_id+':'+image_path,'-'],
                                   cwd=Path(cwd), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        raw = bytearray()
        with selectors.DefaultSelector() as selector:
            for stream, kind in ((process.stdout,'stdout'),(process.stderr,'stderr')):
                os.set_blocking(stream.fileno(),False)
                selector.register(stream,selectors.EVENT_READ,kind)
            while selector.get_map() or process.poll() is None:
                remaining = timeout-(time.monotonic()-started)
                if remaining <= 0:raise Inconclusive('Image copy timeout')
                for key,_ in selector.select(min(remaining,.1)):
                    data = os.read(key.fd,65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    record[key.data+'_bytes'] += len(data)
                    if record['stdout_bytes'] > max_archive_bytes or record['stderr_bytes'] > 65536:
                        raise Inconclusive('Image copy output bound')
                    if key.data=='stdout':raw.extend(data)
        record['exit_code'] = process.returncode
        if process.returncode != 0:raise Inconclusive('Image copy command unavailable')
        if check(0) is not True:raise Inconclusive('Image probe binding changed')
        record.update(inspect_image_archive(bytes(raw),selection,modes,max_archive_bytes=max_archive_bytes))
        record['immutable_image_bound'] = record['outcome']=='image_source_observed'
    except Exception as error:
        record['error_type'] = type(error).__name__
    finally:
        if process is not None:
            kill_group(process)
            for stream in (process.stdout,process.stderr):stream.close()
            record['exit_code'] = process.returncode
        try:verified = check(0) is True
        except Exception as error:
            verified = False;record['final_binding_error_type'] = type(error).__name__
        if not verified:
            record.update(outcome='image_source_incomplete', immutable_image_bound=False,
                          selected_source_bytes_match=None, selected_source_modes_match=None)
        record['ended'] = utc_now()
        atomic_json(directory/'result.json',record)
        attempt.emit('controller','image.source.finished',dict(record,label=label))
    return record
