"""Private Python requirements/installed-metadata dependency closure verification.

Supports plain PEP508 requirements with exact version locks, optional hashes and
environment markers. Other lock representations need independent adapters.
Never imports candidate packages, executes installers or returns raw metadata.
"""
from collections import deque
import hashlib
import json
import re

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version


ENVIRONMENT = {'implementation_name','implementation_version','os_name','platform_machine',
               'platform_release','platform_system','platform_version','python_full_version',
               'platform_python_implementation','python_version','sys_platform'}


class DependencyIncomplete(ValueError):
    """Messages are fixed reason codes; no requirements, URLs or metadata values."""


def requirement(text):
    if not isinstance(text,str) or not 1<=len(text.encode())<=4096:
        raise DependencyIncomplete('requirement_bound')
    try:value=Requirement(text)
    except Exception:raise DependencyIncomplete('requirement_syntax') from None
    if value.url is not None:raise DependencyIncomplete('direct_requirement_unsupported')
    if len(value.name)>128 or len(value.extras)>64:
        raise DependencyIncomplete('requirement_identity_bound')
    if value.marker is not None:
        marker=str(value.marker)
        # Positive extra markers have monotone activation under selected extras.
        # Other extra predicates need installer-specific semantics; refuse them.
        references=len(re.findall(r'\bextra\b',marker))
        positive=len(re.findall(r'\bextra == "[A-Za-z0-9_.-]*"',marker))
        if references!=positive:raise DependencyIncomplete('extra_marker_unsupported')
    return value


def lines(raw):
    if not isinstance(raw,bytes) or not 1<=len(raw)<=262144:
        raise DependencyIncomplete('requirements_file_bound')
    try:text=raw.decode('utf-8')
    except UnicodeError:raise DependencyIncomplete('requirements_encoding') from None
    if '\x00' in text:raise DependencyIncomplete('requirements_encoding')
    result=[];pending=''
    for line in text.splitlines():
        line=re.split(r'\s+#',line,maxsplit=1)[0].strip()
        if not line or line.startswith('#'):continue
        pending+=line[:-1]+' ' if line.endswith('\\') else line
        if len(pending.encode())>8192:raise DependencyIncomplete('requirements_line_bound')
        if line.endswith('\\'):continue
        # Hash annotations are recognized, not verified against installed bytes.
        hashes=re.findall(r'(?:^|\s)--hash=(sha256|sha384|sha512):([0-9a-f]+)(?=\s|$)',pending)
        if any(len(digest)!={'sha256':64,'sha384':96,'sha512':128}[kind] for kind,digest in hashes):
            raise DependencyIncomplete('hash_annotation_syntax')
        pending=re.sub(r'(?:^|\s)--hash=(?:sha256|sha384|sha512):[0-9a-f]+(?=\s|$)',' ',pending).strip()
        if re.search(r'(?:^|\s)--',pending) or pending.startswith('-'):
            raise DependencyIncomplete('requirements_directive_unsupported')
        result.append(requirement(pending));pending=''
        if len(result)>1024:raise DependencyIncomplete('requirements_count_bound')
    if pending or not result:raise DependencyIncomplete('requirements_file_incomplete')
    return result


def active(req,environment,extras=()):
    if req.marker is None:return True
    return any(req.marker.evaluate(environment=dict(environment,extra=extra),context='metadata')
               for extra in ('',*sorted(extras)))


def metadata(report):
    if (not isinstance(report,dict) or report.get('version')!='1'
            or not isinstance(report.get('pip_version'),str) or len(report['pip_version'])>128
            or not isinstance(report.get('installed'),list) or not 1<=len(report['installed'])<=1024
            or not isinstance(report.get('environment'),dict) or set(report['environment'])!=ENVIRONMENT
            or any(not isinstance(v,str) or not v or len(v.encode())>512 for v in report['environment'].values())):
        raise DependencyIncomplete('inspect_report_schema')
    if len(json.dumps(report,allow_nan=False).encode())>4*1024*1024:
        raise DependencyIncomplete('inspect_report_bound')
    Version(report['pip_version']);full=Version(report['environment']['python_full_version'])
    if (not re.fullmatch(r'[0-9]+\.[0-9]+',report['environment']['python_version'])
            or full.release[:2]!=Version(report['environment']['python_version']).release):
        raise DependencyIncomplete('environment_version_conflict')
    distributions={}
    for item in report['installed']:
        if not isinstance(item,dict) or not isinstance(item.get('metadata'),dict):
            raise DependencyIncomplete('distribution_metadata_schema')
        value=item['metadata'];name=value.get('name');version=value.get('version')
        if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9])?',name)
                or not isinstance(version,str) or not 1<=len(version)<=128):
            raise DependencyIncomplete('distribution_identity')
        normalized=canonicalize_name(name)
        if normalized in distributions:raise DependencyIncomplete('duplicate_distribution')
        dependencies=value.get('requires_dist',[]);extras=value.get('provides_extra',[])
        if (not isinstance(dependencies,list) or len(dependencies)>256
                or not isinstance(extras,list) or len(extras)>64
                or any(not isinstance(extra,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',extra) for extra in extras)
                or value.get('requires_python') is not None and (not isinstance(value['requires_python'],str) or len(value['requires_python'])>1024)):
            raise DependencyIncomplete('distribution_dependency_schema')
        distributions[normalized]=dict(version=Version(version),dependencies=[requirement(v) for v in dependencies],
            extras={canonicalize_name(v) for v in extras},python=SpecifierSet(value.get('requires_python') or ''))
    return distributions,report['environment']


def inspect_python_dependencies(locked,declared,report):
    """report is a private, independently bound pip-inspect v1 observation.

    Dependency roots and all active locked rows seed closure. Installed packages
    outside this declared closure are counted separately, never assumed baseline
    tools or application dependencies. Hash annotations, package origin/content,
    actual imports and build/runtime attribution remain separate evidence.
    """
    result=dict(outcome='python_dependencies_incomplete',declared_closure_pinned=None,
                installed_environment_bound=False,artifact_hashes_verified=False,
                application_imports_verified=False,build_consumption_verified=False,
                limits='Declared requirements and installed metadata closure for this environment only; '
                       'not package bytes/origin, actual imports, source/image/runtime binding or complete dependency delivery.')
    try:
        installed,environment=metadata(report)
        locks=lines(locked);roots=lines(declared)
        pins={};requests=[];unversioned=set();pin_extras={}
        for req in locks:
            if not active(req,environment):continue
            name=canonicalize_name(req.name)
            if name in pins or name in unversioned:raise DependencyIncomplete('duplicate_active_lock')
            specifiers=sorted(req.specifier,key=str)
            if any(spec.operator=='===' for spec in specifiers):
                raise DependencyIncomplete('arbitrary_version_lock_unsupported')
            exact=[spec for spec in specifiers if spec.operator=='==' and '*' not in spec.version]
            if not exact:
                unversioned.add(name)
            else:pins[name]=Version(exact[0].version)
            pin_extras[name]={canonicalize_name(extra) for extra in req.extras};requests.append(req)
        requests.extend(req for req in roots if active(req,environment))
        if not requests:raise DependencyIncomplete('empty_active_requirement_scope')
        extras={};pending=deque();seen={};required=set();missing=set();unlocked=set(unversioned)
        conflicts=set();extra_missing=set();python_conflicts=set();edge_count=0
        def select(req):
            name=canonicalize_name(req.name);required.add(name)
            if name not in pins:unlocked.add(name)
            distribution=installed.get(name)
            if distribution is None:missing.add(name);return
            if not req.specifier.contains(distribution['version'],prereleases=True):conflicts.add(name)
            selected=extras.setdefault(name,set());selected.update(canonicalize_name(v) for v in req.extras)
            selected.update(pin_extras.get(name,set()))
            if not selected<=distribution['extras']:extra_missing.add(name)
            pending.append(name)
        for req in requests:select(req)
        while pending:
            name=pending.popleft();context=frozenset(extras[name])
            if seen.get(name)==context:continue
            seen[name]=context;distribution=installed[name]
            if not distribution['python'].contains(environment['python_full_version'],prereleases=True):python_conflicts.add(name)
            for req in distribution['dependencies']:
                edge_count+=1
                if edge_count>8192:raise DependencyIncomplete('dependency_graph_bound')
                if active(req,environment,context):select(req)
        mismatched={name for name,pin in pins.items() if name in installed and installed[name]['version']!=pin}
        missing.update(name for name in pins if name not in installed)
        passed=not (unlocked or mismatched or missing or conflicts or extra_missing or python_conflicts)
        scope=sorted((name,str(installed[name]['version']),sorted(extras.get(name,set()))) for name in required if name in installed)
        result.update(outcome='python_dependency_closure_observed',declared_closure_pinned=passed,
            locked_version_count=len(pins),required_distribution_count=len(required),
            unlocked_dependency_count=len(unlocked),version_mismatch_count=len(mismatched),missing_distribution_count=len(missing),
            constraint_conflict_count=len(conflicts),unavailable_extra_count=len(extra_missing),python_conflict_count=len(python_conflicts),
            unmapped_installed_count=len(set(installed)-required),
            declared_scope_sha256=hashlib.sha256(json.dumps(scope,sort_keys=True).encode()).hexdigest(),
            environment_sha256=hashlib.sha256(json.dumps(environment,sort_keys=True).encode()).hexdigest(),
            lock_sha256=hashlib.sha256(locked).hexdigest(),declared_sha256=hashlib.sha256(declared).hexdigest())
    except Exception as error:result['error_type']=type(error).__name__
    return result
