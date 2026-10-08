"""Private npm v3 lock version inventory; consistency belongs to native npm ci."""
import base64
import hashlib
import json
import re
import urllib.parse


GROUPS = ('dependencies','devDependencies','optionalDependencies','peerDependencies')
VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
                     r'(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][A-Za-z0-9-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][A-Za-z0-9-]*))*)?'
                     r'(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?')


class NpmInventoryIncomplete(ValueError):pass


def document(raw):
    if not isinstance(raw,bytes) or not 1<=len(raw)<=4*1024*1024:
        raise NpmInventoryIncomplete('document_bound')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise NpmInventoryIncomplete('duplicate_json_key')
            result[key]=value
        return result
    def constant(_):raise NpmInventoryIncomplete('nonfinite_json')
    try:value=json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
    except Exception:raise NpmInventoryIncomplete('document_schema') from None
    if not isinstance(value,dict):raise NpmInventoryIncomplete('document_schema')
    return value


def dependency_groups(value):
    total=0
    for group in GROUPS:
        entries=value.get(group,{})
        if not isinstance(entries,dict) or len(entries)>1024:
            raise NpmInventoryIncomplete('dependency_group_bound')
        for name,specification in entries.items():
            if (not isinstance(name,str) or not 1<=len(name)<=214 or any(ord(c)<32 for c in name)
                    or not isinstance(specification,str) or not 1<=len(specification)<=4096):
                raise NpmInventoryIncomplete('dependency_identity')
        total+=len(entries)
    return total


def package_path(value):
    if not isinstance(value,str) or not 1<=len(value)<=2048 or '\\' in value:
        raise NpmInventoryIncomplete('package_path')
    parts=value.split('/');position=0
    while position<len(parts):
        if parts[position]!='node_modules':raise NpmInventoryIncomplete('package_layout_unsupported')
        position+=1
        if position>=len(parts):raise NpmInventoryIncomplete('package_path')
        name=parts[position];position+=1
        if name.startswith('@'):
            if not re.fullmatch(r'@[A-Za-z0-9_.-]+',name) or position>=len(parts):
                raise NpmInventoryIncomplete('scoped_package_path')
            name=parts[position];position+=1
        if name in ('.','..','') or not re.fullmatch(r'[A-Za-z0-9_.-]+',name):
            raise NpmInventoryIncomplete('package_path')


def resolution(value):
    if value is None:return
    if not isinstance(value,str) or not 1<=len(value)<=4096 or any(ord(c)<32 for c in value):
        raise NpmInventoryIncomplete('resolution_schema')
    parsed=urllib.parse.urlsplit(value)
    if (parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise NpmInventoryIncomplete('resolution_layout_unsupported')


def integrity(value):
    if value is None:return False
    if not isinstance(value,str) or not 1<=len(value)<=4096:
        raise NpmInventoryIncomplete('integrity_schema')
    tokens = value.split()
    if not tokens:
        raise NpmInventoryIncomplete('integrity_schema')
    for token in tokens:
        match=re.fullmatch(r'(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})',token)
        if not match:raise NpmInventoryIncomplete('integrity_layout_unsupported')
        try:decoded=base64.b64decode(match[2],validate=True)
        except Exception:raise NpmInventoryIncomplete('integrity_encoding') from None
        if len(decoded)!={'sha256':32,'sha384':48,'sha512':64}[match[1]]:
            raise NpmInventoryIncomplete('integrity_encoding')
    return True


def inspect_npm_versions(manifest_bytes,lock_bytes):
    """Return counts/digests, never package names, URLs or parser diagnostics.

    Standard nonworkspace package-lock v3 registry entries only. This is not a
    graph/semver-range resolver: manifest consistency must use pinned native npm
    with the actual configuration and required registry metadata/cache.
    """
    result=dict(outcome='npm_version_inventory_incomplete',recorded_versions_fixed=None,
                native_consistency_verified=False,installed_environment_bound=False,
                artifact_integrity_verified=False,build_consumption_verified=False,
                limits='Recorded registry-package versions only; native manifest/lock consistency, '
                       'installed packages, artifact bytes, actual configuration and source/build/runtime binding remain separate.')
    try:
        manifest=document(manifest_bytes);lock=document(lock_bytes)
        if manifest.get('workspaces') is not None or lock.get('lockfileVersion')!=3 or type(lock.get('lockfileVersion')) is not int:
            raise NpmInventoryIncomplete('lock_representation_unsupported')
        packages=lock.get('packages')
        if (not isinstance(packages,dict) or not 2<=len(packages)<=4097
                or not isinstance(packages.get(''),dict)):
            raise NpmInventoryIncomplete('package_inventory_bound')
        root_count=dependency_groups(manifest);dependency_groups(packages[''])
        counters=dict(package_count=0,fixed_version_count=0,unfixed_version_count=0,
                      optional_package_count=0,dev_package_count=0,peer_package_count=0,
                      integrity_annotation_count=0,declared_root_entry_count=root_count)
        for path,entry in packages.items():
            if path=='':continue
            package_path(path)
            if not isinstance(entry,dict) or entry.get('link',False) is not False:
                raise NpmInventoryIncomplete('linked_package_unsupported')
            dependency_groups(entry);resolution(entry.get('resolved'))
            for flag in ('dev','optional','peer','devOptional','inBundle','hasInstallScript'):
                if flag in entry and type(entry[flag]) is not bool:raise NpmInventoryIncomplete('package_flag_schema')
            version=entry.get('version')
            if version is not None and (not isinstance(version,str) or len(version)>256):
                raise NpmInventoryIncomplete('package_version_schema')
            fixed=version is not None and VERSION.fullmatch(version) is not None
            counters['package_count']+=1
            counters['fixed_version_count' if fixed else 'unfixed_version_count']+=1
            for flag in ('optional','dev','peer'):
                if entry.get(flag,False):counters[flag+'_package_count']+=1
            counters['integrity_annotation_count']+=int(integrity(entry.get('integrity')))
        result.update(outcome='npm_version_inventory_observed',recorded_versions_fixed=counters['unfixed_version_count']==0,
                      manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),lock_sha256=hashlib.sha256(lock_bytes).hexdigest(),**counters)
    except Exception as error:result['error_type']=type(error).__name__
    return result
