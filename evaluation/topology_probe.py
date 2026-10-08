"""Standalone sandbox-side topology observation; raw Kubernetes data stays local."""
import argparse
import ipaddress
import json
import re
import subprocess
import time
import uuid


ROLES = {'web', 'api', 'worker', 'database', 'storage'}
SERVICE_ROLES = ROLES - {'worker'}
KINDS = {'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Pod'}
NAME = re.compile(r'[a-z0-9][a-z0-9.-]{0,252}')
REFERENCE = re.compile(r'[A-Za-z0-9._:/-]+(?:@sha256:[0-9a-f]{64})?')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def unique_pairs(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError('Duplicate Kubernetes JSON field')
        value[name] = item
    return value


def identity(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('Canonical Kubernetes UID required')
    return value


def mapping(value):
    if (not isinstance(value, dict) or set(value) != {'components', 'services'}
            or not isinstance(value['components'], dict) or set(value['components']) != ROLES
            or not isinstance(value['services'], dict) or set(value['services']) != SERVICE_ROLES):
        raise ValueError('Complete operator-selected role/service mapping required')
    for role, item in value['components'].items():
        if (not isinstance(item, dict) or set(item) != {'kind', 'name', 'container'}
                or item['kind'] not in KINDS
                or any(not isinstance(item[key], str) or not NAME.fullmatch(item[key])
                       for key in ('name', 'container'))):
            raise ValueError('Explicit workload/container identity required')
    if value['components']['worker']['kind'] != 'Deployment':
        raise ValueError('APP-001 requires a worker Deployment')
    for name in value['services'].values():
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError('Explicit internal Service identity required')
    return value


def owner(value):
    refs = [item for item in value['metadata'].get('ownerReferences', [])
            if item.get('controller') is True]
    if len(refs) > 1:
        raise ValueError('Ambiguous controller ownership')
    return (refs[0]['kind'], identity(refs[0]['uid'])) if refs else None


def scope(namespaces, namespace):
    values = namespaces['items']
    if not isinstance(values, list) or len(values) != 2:
        raise ValueError('Exactly two namespace anchors required')
    by_name = {value['metadata']['name']: value for value in values}
    if set(by_name) != {'kube-system', namespace} or any(value['kind'] != 'Namespace' for value in values):
        raise ValueError('Incorrect namespace anchors')
    if len({value['metadata']['uid'] for value in values}) != 2:
        raise ValueError('Distinct namespace anchors required')
    if any(value['metadata'].get('deletionTimestamp') for value in values):
        raise ValueError('Namespace anchor is being deleted')
    return dict(namespace=namespace,
                kube_system_uid=identity(by_name['kube-system']['metadata']['uid']),
                namespace_uid=identity(by_name[namespace]['metadata']['uid']))


def image(container, status):
    declared, reported = container['image'], status['imageID']
    if (not isinstance(declared, str) or not REFERENCE.fullmatch(declared)
            or '://' in declared or not isinstance(reported, str)):
        raise ValueError('Unsafe image identity')
    bare = reported
    for prefix in ('docker-pullable://', 'containerd://', 'docker://'):
        if bare.startswith(prefix):
            bare = bare.removeprefix(prefix)
            break
    digest = bare.rsplit('@', 1)[-1]
    if not DIGEST.fullmatch(digest) or (bare != digest and not REFERENCE.fullmatch(bare)):
        raise ValueError('Unrecognized runtime image identity')
    return dict(declared_reference=declared, reference_uses_digest='@sha256:' in declared,
                runtime_image_id=reported, runtime_digest=digest)


def project(objects, selected, namespace='incident-app'):
    selected = mapping(selected)
    items = objects['items']
    if not isinstance(items, list) or not 1 <= len(items) <= 4096:
        raise ValueError('Bounded live topology required')
    by_key = {}; by_uid = {}
    for item in items:
        meta = item['metadata']; kind = item['kind']
        if (meta['namespace'] != namespace or not NAME.fullmatch(meta['name'])
                or kind not in KINDS | {'Service', 'EndpointSlice'}):
            raise ValueError('Unexpected namespaced topology object')
        uid = identity(meta['uid']); key = kind, meta['name']
        if key in by_key or uid in by_uid:
            raise ValueError('Duplicate live topology identity')
        by_key[key] = item; by_uid[uid] = item
    components = {}; pod_ids = {}
    for role, assigned in selected['components'].items():
        key = assigned['kind'], assigned['name']
        workload = by_key[key]; uid = workload['metadata']['uid']
        if workload['metadata'].get('deletionTimestamp'):
            raise ValueError('Selected workload is being deleted')
        pods = []
        for item in items:
            if item['kind'] != 'Pod':
                continue
            if key[0] == 'Pod':
                included = item['metadata']['uid'] == uid
            elif key[0] == 'Deployment':
                ref = owner(item)
                parent = by_uid.get(ref[1]) if ref and ref[0] == 'ReplicaSet' else None
                included = parent is not None and parent['kind'] == 'ReplicaSet' and owner(parent) == ('Deployment', uid)
            else:
                included = owner(item) == (key[0], uid)
            if included:
                pods.append(item)
        state = workload.get('status', {})
        generation = None
        if key[0] == 'Pod':
            replicas = 1
        else:
            generation = workload['metadata']['generation']
            observed = state.get('observedGeneration', 0)
            if type(generation) is not int or type(observed) is not int or observed < generation:
                raise ValueError('Controller has not observed the selected generation')
            replicas = state.get('desiredNumberScheduled') if key[0] == 'DaemonSet' else workload['spec'].get('replicas', 1)
        if type(replicas) is not int or not 1 <= replicas <= 1000 or len(pods) != replicas:
            raise ValueError('Selected workload replica population incomplete')
        observations = []
        for pod in pods:
            meta, spec, status = pod['metadata'], pod['spec'], pod.get('status', {})
            if (meta.get('deletionTimestamp') or status.get('phase') != 'Running'
                    or not any(c.get('type') == 'Ready' and c.get('status') == 'True'
                               for c in status.get('conditions', []))):
                raise ValueError('Selected Pod is not live and ready')
            containers = spec['containers']; statuses = status.get('containerStatuses', [])
            if (len({c['name'] for c in containers}) != len(containers)
                    or len({c['name'] for c in statuses}) != len(statuses)
                    or {c['name'] for c in containers} != {c['name'] for c in statuses}):
                raise ValueError('Incomplete container statuses')
            declared = {c['name']: c for c in containers}; actual = {c['name']: c for c in statuses}
            if any(c.get('ready') is not True or set(c.get('state', {})) != {'running'} for c in statuses):
                raise ValueError('Selected workload has a nonrunning container')
            primary = assigned['container']
            observed_image = image(declared[primary], actual[primary])
            addresses = status.get('podIPs', [{'ip': status.get('podIP')}])
            ips = []
            for address in addresses:
                parsed = ipaddress.ip_address(address['ip'])
                if not parsed.is_private or parsed.is_loopback or parsed.is_unspecified:
                    raise ValueError('Private nonloopback Pod address required')
                ips.append(str(parsed))
            observations.append(dict(name=meta['name'], uid=meta['uid'], addresses=sorted(ips),
                                     container=primary, **observed_image))
        pod_ids[role] = {pod['uid']: pod for pod in observations}
        components[role] = dict(kind=key[0], name=key[1], uid=uid, generation=generation,
                                ready_replicas=replicas, pods=sorted(observations, key=lambda pod: pod['name']))
    worker = components['worker']['uid']
    if any(value['uid'] == worker for role, value in components.items() if role != 'worker'):
        raise ValueError('Worker Deployment must be separate from other roles')
    services = {}
    for role, name in selected['services'].items():
        service = by_key['Service', name]; spec = service['spec']
        service_type = spec.get('type', 'ClusterIP')
        if (service['metadata'].get('deletionTimestamp')
                or service_type not in ('ClusterIP', 'NodePort', 'LoadBalancer')):
            raise ValueError('Ordinary live Service with a ClusterIP required')
        cluster_ip = ipaddress.ip_address(spec['clusterIP'])
        if not cluster_ip.is_private or cluster_ip.is_loopback or cluster_ip.is_unspecified:
            raise ValueError('Private nonloopback ClusterIP required')
        ports = spec['ports']
        if (not isinstance(ports, list) or not ports
                or any(p.get('protocol', 'TCP') != 'TCP' or type(p['port']) is not int
                       or not 1 <= p['port'] <= 65535 for p in ports)):
            raise ValueError('Complete TCP Service ports required')
        endpoints = set()
        for item in items:
            if item['kind'] != 'EndpointSlice' or item['metadata'].get('labels', {}).get('kubernetes.io/service-name') != name:
                continue
            if item['metadata'].get('deletionTimestamp') or owner(item) != ('Service', service['metadata']['uid']):
                raise ValueError('EndpointSlice ownership unavailable')
            for endpoint in item['endpoints']:
                if endpoint.get('conditions', {}).get('ready') is not True:
                    raise ValueError('Service endpoint is not ready')
                ref = endpoint['targetRef']
                if ref['kind'] != 'Pod' or ref.get('namespace', namespace) != namespace or ref['uid'] not in pod_ids[role]:
                    raise ValueError('Service routes outside its independently mapped workload')
                target = pod_ids[role][ref['uid']]
                if ref['name'] != target['name'] or not endpoint['addresses'] or not {str(ipaddress.ip_address(address)) for address in endpoint['addresses']} <= set(target['addresses']):
                    raise ValueError('Service endpoint address/identity mismatch')
                endpoints.add(ref['uid'])
        if endpoints != set(pod_ids[role]):
            raise ValueError('Service does not cover the mapped ready Pods')
        services[role] = dict(name=name, uid=service['metadata']['uid'], type=service_type,
                              cluster_ip=str(cluster_ip), ports=sorted(p['port'] for p in ports),
                              target_pod_uids=sorted(endpoints))
    return dict(components=components, services=services)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubectl-prefix', required=True)
    parser.add_argument('--mapping', required=True)
    args = parser.parse_args()
    report = dict(outcome='topology_observation_incomplete')
    statuses = []
    deadline = time.monotonic() + 60
    try:
        prefix = json.loads(args.kubectl_prefix)
        selected = mapping(json.loads(args.mapping, object_pairs_hook=unique_pairs))
        if (not isinstance(prefix, list) or not 1 <= len(prefix) <= 16
                or any(not isinstance(v, str) or not 0 < len(v) <= 1024 for v in prefix)):
            raise ValueError('Bounded trusted kubectl prefix required')
        def query(argv):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Topology collection deadline')
            result = subprocess.run([*prefix, *argv], stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=min(15, remaining))
            statuses.append(result.returncode)
            if result.returncode or len(result.stdout) > 16*1024**2:
                raise ValueError('Topology query unavailable or oversized')
            return json.loads(result.stdout, object_pairs_hook=unique_pairs)
        def observe():
            anchors = scope(query(['get', 'namespaces', 'kube-system', 'incident-app', '-o', 'json']), 'incident-app')
            value = project(query(['-n', 'incident-app', 'get',
                'deployments,statefulsets,daemonsets,replicasets,pods,services,endpointslices', '-o', 'json']), selected)
            return dict(scope=anchors, **value)
        before, after = observe(), observe()
        if before != after:
            raise ValueError('Selected live topology changed during collection')
        report.update(outcome='stable_topology_observed', observation=before,
                      limits='Bracketed selected topology/API-reported image IDs only; kube-system UID is a cluster anchor, not a canonical cluster ID. No technology, network-policy, source/image artifact, migration or storage acceptance proof.')
    except Exception as error:
        report['error_type'] = type(error).__name__
    report['query_exit_codes'] = statuses
    print(json.dumps(report, sort_keys=True))
    return int(report['outcome'] != 'stable_topology_observed')


if __name__ == '__main__':
    raise SystemExit(main())
