"""Private installed metadata from an inert image filesystem archive.

Run the observer in a trusted pinned base with Python -I -S. stdin is an
uncompressed Docker cp archive; stdout contains PRIVATE normalized metadata.
Never log stdout or extract/import anything from the candidate archive. Marker
environment belongs to the trusted observer, not an attested application process.
"""
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import PurePosixPath
import platform
import re
import sys
import tarfile


class MetadataUnavailable(ValueError):
    """Fixed refusal messages; archive names and metadata are private."""
    def __init__(self, reason, metadata_version=None):
        super().__init__(reason)
        self.metadata_version = (metadata_version if isinstance(metadata_version,str)
                                 and re.fullmatch('[0-9]{1,2}\\.[0-9]{1,2}',metadata_version) else None)


class BoundedInput:
    def __init__(self, stream, limit):
        self.stream, self.limit = stream, limit
        self.bytes = self.zero_tail = 0
        self.digest = hashlib.sha256()

    def read(self, count=-1):
        count = min(count if count >= 0 else 65536, 65536)
        value = self.stream.read(count)
        self.bytes += len(value)
        if self.bytes > self.limit:raise MetadataUnavailable('archive_bound')
        self.digest.update(value)
        stripped = value.rstrip(b'\0')
        self.zero_tail = len(value)-len(stripped) if stripped else self.zero_tail+len(value)
        return value


def environment():
    if sys.implementation.name != 'cpython':
        raise MetadataUnavailable('python_observer_profile')
    version = platform.python_version()
    return dict(implementation_name=sys.implementation.name, implementation_version=version,
                os_name=os.name, platform_machine=platform.machine(),
                platform_release=platform.release(), platform_system=platform.system(),
                platform_version=platform.version(), python_full_version=version,
                platform_python_implementation=platform.python_implementation(),
                python_version='.'.join(version.split('.')[:2]), sys_platform=sys.platform)


def inspect_python_image_archive(stream, *, max_bytes=256*1024**2):
    """Return private metadata and safe counts/hashes; unsupported layouts refuse.

    Only top-level .dist-info/METADATA represents installed distributions in this
    profile. Startup hooks are counted and hashed but never run. Extra installed
    distributions are retained for the closure verifier, not silently discarded.
    """
    if type(max_bytes) is not int or not 1024 <= max_bytes <= 256*1024**2:
        raise ValueError('Bounded private image archive required')
    reader = BoundedInput(stream,max_bytes)
    seen, files, distributions, directories = set(), [], {}, set()
    total = entries = hooks = import_fields = 0
    metadata_versions = {}
    with tarfile.open(fileobj=reader,mode='r|') as archive:
        for member in archive:
            entries += 1
            name = member.name.rstrip('/') if member.isdir() else member.name
            path = PurePosixPath(name)
            if (entries > 16384 or not name or name == '.' or len(name) > 4096 or name in seen
                    or path.is_absolute() or '..' in path.parts or str(path) != name
                    or '\\' in name or any(ord(c) < 32 for c in name)
                    or path.parts[0] != 'site-packages'
                    or member.type not in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE)
                    or member.sparse is not None or member.linkname or not 0 <= member.mode <= 0o7777):
                raise MetadataUnavailable('archive_layout')
            seen.add(name)
            if len(path.parts) >= 2 and path.parts[1].endswith('.egg-info'):
                raise MetadataUnavailable('legacy_metadata_layout')
            if len(path.parts) >= 2 and path.parts[1].endswith('.dist-info'):
                directories.add(path.parts[1])
            if member.isdir():
                if member.size:raise MetadataUnavailable('directory_payload')
                continue
            if len(files) >= 8192 or not 0 <= member.size <= 32*1024**2:
                raise MetadataUnavailable('file_bound')
            selected = len(path.parts)==3 and path.parts[1].endswith('.dist-info') and path.name=='METADATA'
            if selected and member.size > 1024*1024:raise MetadataUnavailable('metadata_bound')
            digest = hashlib.sha256();body = bytearray();length = 0
            content = archive.extractfile(member)
            if content is None:raise MetadataUnavailable('file_payload')
            with content:
                while True:
                    chunk = content.read(65536)
                    if not chunk:break
                    length += len(chunk);digest.update(chunk)
                    if selected:body.extend(chunk)
            if length != member.size:raise MetadataUnavailable('truncated_payload')
            total += length
            files.append((name,member.size,member.mode,digest.hexdigest()))
            hooks += int(len(path.parts)==2 and path.suffix=='.pth')
            if selected:
                try:
                    bytes(body).decode('utf-8')
                    headers = BytesParser().parsebytes(bytes(body),headersonly=True)
                    if headers.defects:raise ValueError()
                    if any(len(headers.get_all(key,[])) != 1 for key in ('Name','Version','Metadata-Version')):
                        raise ValueError()
                    metadata_version = str(headers['Metadata-Version'])
                    if metadata_version not in ('2.1','2.2','2.3','2.4','2.5','2.6'):
                        raise MetadataUnavailable('metadata_version_unsupported',metadata_version)
                    if len(headers.get_all('Requires-Python',[])) > 1:raise ValueError()
                    value = dict(name=str(headers['Name']),version=str(headers['Version']),
                                 requires_dist=[str(v) for v in headers.get_all('Requires-Dist',[])],
                                 provides_extra=[str(v) for v in headers.get_all('Provides-Extra',[])],
                                 import_name=[str(v) for v in headers.get_all('Import-Name',[])],
                                 import_namespace=[str(v) for v in headers.get_all('Import-Namespace',[])])
                    if headers.get('Requires-Python') is not None:
                        value['requires_python'] = str(headers['Requires-Python'])
                except MetadataUnavailable:raise
                except Exception:raise MetadataUnavailable('metadata_headers') from None
                metadata_versions[metadata_version] = metadata_versions.get(metadata_version,0)+1
                import_fields += len(value['import_name'])+len(value['import_namespace'])
                distributions[path.parts[1]] = dict(metadata=value)
        end = archive.offset
    while reader.read(65536):pass
    if (reader.bytes%512 or reader.bytes < end+1024
            or reader.bytes-reader.zero_tail > end):
        raise MetadataUnavailable('archive_end')
    file_names = {row[0] for row in files}
    if any(str(parent) in file_names for name in seen for parent in PurePosixPath(name).parents):
        raise MetadataUnavailable('archive_ancestry')
    if not 1 <= len(distributions) <= 1024 or set(distributions) != directories:
        raise MetadataUnavailable('incomplete_distribution_metadata')
    installed = [distributions[name] for name in sorted(distributions)]
    pip = [item['metadata']['version'] for item in installed if item['metadata']['name'].lower()=='pip']
    if len(pip) != 1:raise MetadataUnavailable('pip_metadata_identity')
    report = dict(version='1',pip_version=pip[0],environment=environment(),installed=installed)
    if len(json.dumps(report).encode()) > 4*1024**2:raise MetadataUnavailable('report_bound')
    receipt = dict(archive_bytes=reader.bytes,archive_sha256=reader.digest.hexdigest(),
                   installed_files=len(files),installed_bytes=total,
                   installed_tree_sha256=hashlib.sha256(json.dumps(sorted(files)).encode()).hexdigest(),
                   distribution_count=len(installed),startup_hook_files=hooks,
                   metadata_versions=metadata_versions,
                   import_metadata_fields=import_fields,import_metadata_verified=False,
                   candidate_packages_executed=False,candidate_archive_extracted=False,
                   marker_context='trusted-observer',application_environment_verified=False)
    return dict(metadata=report,receipt=receipt)


if __name__=='__main__':
    if not sys.flags.isolated or not sys.flags.no_site:
        raise SystemExit('Private observer requires -I -S')
    try:print(json.dumps(inspect_python_image_archive(sys.stdin.buffer)))
    except Exception as error:
        print(json.dumps(dict(outcome='image_metadata_incomplete',error_type=type(error).__name__,
                             reason=str(error) if isinstance(error,MetadataUnavailable) else None,
                             metadata_version=getattr(error,'metadata_version',None))))
        raise SystemExit(1)
