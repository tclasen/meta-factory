"""Private Docker copy observations of selected source in immutable images.

No archive is extracted, application entrypoint run, or source content returned.
This establishes selected filesystem bytes/modes, not how they were built or
whether a deployed process consumes them.
"""
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import tarfile


def selection_records(selection, modes):
    if (not isinstance(selection, dict) or not selection or len(selection) > 4096
            or not isinstance(modes, dict) or set(modes) != set(selection)):
        raise ValueError('Complete bounded source selection and modes required')
    paths = set()
    for source, value in selection.items():
        if (not isinstance(source, str) or not source or not isinstance(value, dict)
                or source == '.' or PurePosixPath(source).is_absolute()
                or '..' in PurePosixPath(source).parts or str(PurePosixPath(source)) != source
                or '\\' in source or any(ord(c) < 32 for c in source)
                or set(value) != {'archive_path', 'sha256', 'size', 'executable'}):
            raise ValueError('Explicit captured source/image mapping required')
        name = value['archive_path']
        if (not isinstance(name, str) or not name or name == '.'
                or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                or str(PurePosixPath(name)) != name or '\\' in name
                or any(ord(c) < 32 for c in name) or name in paths
                or not isinstance(value['sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', value['sha256'])
                or type(value['size']) is not int or not 0 <= value['size'] <= 8*1024**2
                or type(value['executable']) is not bool
                or type(modes[source]) is not int or not 0 <= modes[source] <= 0o777
                or bool(modes[source] & 0o111) != value['executable']):
            raise ValueError('Unsupported source/image selection')
        paths.add(name)
    return selection


def inspect_image_archive(raw, selection, modes, *, max_archive_bytes=64*1024**2):
    """Parse an uncompressed private Docker cp archive without extracting it.

    Complete known mismatches are False; unsupported/corrupt/truncated archives
    stay unknown. The caller separately binds exact stopped container/image and
    captured selection identities. Extra regular files are outside the selection.
    """
    selection_records(selection, modes)
    if type(max_archive_bytes) is not int or not 1024 <= max_archive_bytes <= 64*1024**2:
        raise ValueError('Bounded image archive required')
    result = dict(outcome='image_source_incomplete', selected_source_bytes_match=None,
                  selected_source_modes_match=None, selected_files=len(selection),
                  archive_files=None, outside_selection_files=None,
                  application_execution_verified=False, deployed_image_verified=False,
                  build_consumption_verified=False)
    try:
        if (not isinstance(raw, bytes) or not 1024 <= len(raw) <= max_archive_bytes
                or len(raw) % 512):
            raise ValueError()
        observed, seen, entries = {}, set(), 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                entries += 1
                name = member.name.rstrip('/') if member.isdir() else member.name
                if (entries > 8192 or not name or name == '.' or name in seen
                        or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                        or str(PurePosixPath(name)) != name or '\\' in name
                        or any(ord(c) < 32 for c in name) or len(name) > 4096
                        or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                        or member.sparse is not None or member.linkname
                        or not 0 <= member.mode <= 0o7777):
                    raise ValueError()
                seen.add(name)
                if member.isdir():
                    if member.size != 0:raise ValueError()
                    continue
                if len(observed) >= 4096 or not 0 <= member.size <= 8*1024**2:
                    raise ValueError()
                stream = archive.extractfile(member)
                if stream is None:raise ValueError()
                with stream:
                    content = stream.read(member.size+1)
                if len(content) != member.size:raise ValueError()
                observed[name] = dict(size=member.size, mode=member.mode,
                                      sha256=hashlib.sha256(content).hexdigest())
            # tarfile stops at the first zero header. Require a complete two-block
            # end marker and zero padding, rather than accepting truncation or an
            # appended second archive that its iterator would silently ignore.
            end = archive.offset
            if end+1024 > len(raw) or any(raw[end:]):raise ValueError()
        if any(str(parent) in observed for name in seen for parent in PurePosixPath(name).parents):
            raise ValueError()
        bytes_match = modes_match = True
        for source, expected in selection.items():
            value = observed.get(expected['archive_path'])
            bytes_match &= (value is not None and value['size'] == expected['size']
                            and value['sha256'] == expected['sha256'])
            modes_match &= value is not None and value['mode'] == modes[source]
        scope = dict(selection=selection, modes=modes)
        result.update(outcome='image_source_observed', selected_source_bytes_match=bool(bytes_match),
                      selected_source_modes_match=bool(modes_match), archive_files=len(observed),
                      outside_selection_files=len(set(observed)-{r['archive_path'] for r in selection.values()}),
                      selection_sha256=hashlib.sha256(json.dumps(scope,sort_keys=True).encode()).hexdigest(),
                      archive_sha256=hashlib.sha256(raw).hexdigest())
    except (ValueError, TypeError, OSError, tarfile.TarError, OverflowError):
        pass
    return result
