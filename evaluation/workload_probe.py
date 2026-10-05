"""Trusted sandbox-side workload observation and conditional replica changes."""

import argparse
import json
import re
import subprocess
import time


NAME = re.compile(r'[a-z0-9][a-z0-9.-]{0,252}')
KINDS = {'deployment': 'Deployment', 'statefulset': 'StatefulSet'}


def controller_uid(value, kind):
    owners = [o for o in value.get('metadata', {}).get('ownerReferences', [])
              if o.get('controller') is True and o.get('kind') == kind]
    return owners[0]['uid'] if len(owners) == 1 else None


def pod_running(pod):
    """All declared regular containers and restartable init sidecars have processes.

    This deliberately does not require dependency readiness or startup-probe
    success. Running is a process observation, not proof of useful queue work.
    """
    if pod.get('status', {}).get('phase') != 'Running':
        return False
    spec, status = pod.get('spec', {}), pod.get('status', {})
    containers = spec.get('containers', [])
    sidecars = [c for c in spec.get('initContainers', []) if c.get('restartPolicy') == 'Always']
    expected = [c.get('name') for c in containers + sidecars]
    if not containers or any(not isinstance(name, str) or not name for name in expected) or len(set(expected)) != len(expected):
        return False
    observed = status.get('containerStatuses', []) + [c for c in status.get('initContainerStatuses', []) if c.get('name') in {c.get('name') for c in sidecars}]
    if len(observed) != len(expected) or {c.get('name') for c in observed} != set(expected):
        return False
    return all(set(c.get('state', {})) == {'running'}
               and isinstance(c['state']['running'], dict)
               and isinstance(c['state']['running'].get('startedAt'), str)
               and bool(c['state']['running']['startedAt']) for c in observed)


def project(workload, replica_sets, pods, namespace, kind, name):
    meta = workload['metadata']
    if meta['namespace'] != namespace or meta['name'] != name or workload['kind'] != KINDS[kind]:
        raise ValueError('Unexpected workload identity')
    if meta.get('deletionTimestamp'):
        raise ValueError('Workload is being deleted')
    replicas = workload['spec'].get('replicas', 1)
    if type(replicas) is not int or not 0 <= replicas <= 100:
        raise ValueError('Unsupported replica count')
    uid, version = meta['uid'], meta['resourceVersion']
    if not NAME.fullmatch(uid) or not isinstance(version, str) or not version.isdecimal():
        raise ValueError('Invalid workload identity')
    descendants = {item['metadata']['uid'] for item in replica_sets
                   if item['metadata']['namespace'] == namespace
                   and controller_uid(item, 'Deployment') == uid}
    selected = []
    for pod in pods:
        if pod['metadata']['namespace'] != namespace:
            raise ValueError('Unexpected Pod namespace')
        owned = (controller_uid(pod, 'ReplicaSet') in descendants if kind == 'deployment'
                 else controller_uid(pod, 'StatefulSet') == uid)
        if owned:
            metadata = pod['metadata']
            if not NAME.fullmatch(metadata['name']) or not NAME.fullmatch(metadata['uid']):
                raise ValueError('Invalid Pod identity')
            selected.append({'name': metadata['name'], 'uid': metadata['uid'],
                             'terminating': bool(metadata.get('deletionTimestamp')),
                             'running': pod_running(pod),
                             'ready': any(c.get('type') == 'Ready' and c.get('status') == 'True'
                                          for c in pod.get('status', {}).get('conditions', []))})
    return {'namespace': namespace, 'kind': kind, 'name': name, 'uid': uid,
            'resource_version': version, 'replicas': replicas,
            'generation': meta['generation'],
            'observed_generation': workload.get('status', {}).get('observedGeneration', 0),
            'pods': sorted(selected, key=lambda item: item['name'])}


def scale_patch(snapshot, expected_uid, expected_replicas, replicas):
    if snapshot['uid'] != expected_uid or snapshot['replicas'] != expected_replicas:
        raise ValueError('Workload changed since fault preparation')
    if type(replicas) is not int or not 0 <= replicas <= 100:
        raise ValueError('Invalid target replica count')
    return [{'op': 'test', 'path': '/metadata/uid', 'value': expected_uid},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': snapshot['resource_version']},
            {'op': 'test', 'path': '/spec/replicas', 'value': expected_replicas},
            {'op': 'replace', 'path': '/spec/replicas', 'value': replicas}]


def converged(snapshot, uid, replicas, *, convergence='ready'):
    if convergence not in ('ready', 'running'):
        raise ValueError('Invalid workload convergence mode')
    if snapshot['uid'] != uid or snapshot['replicas'] != replicas:
        raise ValueError('Workload identity or replica target changed')
    if snapshot['observed_generation'] < snapshot['generation']:
        return False
    return len(snapshot['pods']) == replicas and all(p.get(convergence) is True and not p['terminating'] for p in snapshot['pods'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubectl-prefix', required=True)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--kind', choices=KINDS, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--operation', choices=('inspect', 'scale'), required=True)
    parser.add_argument('--convergence', choices=('ready', 'running'), default='ready')
    parser.add_argument('--expected-uid')
    parser.add_argument('--expected-replicas', type=int)
    parser.add_argument('--replicas', type=int)
    args = parser.parse_args()
    report = {'outcome': 'workload_operation_incomplete', 'query_exit_codes': [], 'mutation_attempted': False}
    deadline = time.monotonic() + 120
    try:
        prefix = json.loads(args.kubectl_prefix)
        if (not isinstance(prefix, list) or not 1 <= len(prefix) <= 16
                or not all(isinstance(a, str) and 0 < len(a) <= 1024 for a in prefix)
                or not all(NAME.fullmatch(a) for a in (args.namespace, args.name))):
            raise ValueError('Invalid workload query')
        def query(argv):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Workload operation deadline')
            result = subprocess.run([*prefix, '-n', args.namespace, *argv], capture_output=True,
                                    stdin=subprocess.DEVNULL, timeout=min(15, remaining))
            report['query_exit_codes'].append(result.returncode)
            if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
                raise RuntimeError('Workload query failed')
            return json.loads(result.stdout)
        def observe():
            workload = query(['get', args.kind, args.name, '-o', 'json'])
            sets = query(['get', 'replicasets', '-o', 'json'])['items'] if args.kind == 'deployment' else []
            pods = query(['get', 'pods', '-o', 'json'])['items']
            return project(workload, sets, pods, args.namespace, args.kind, args.name)
        snapshot = observe()
        report['before'] = snapshot
        if args.operation == 'inspect':
            report.update(outcome='workload_observed', workload=snapshot)
        else:
            patch = scale_patch(snapshot, args.expected_uid, args.expected_replicas, args.replicas)
            if snapshot['replicas'] != args.replicas:
                report['mutation_attempted'] = True
                query(['patch', args.kind, args.name, '--type=json', '-p', json.dumps(patch), '-o', 'json'])
            while True:
                snapshot = observe()
                report['workload'] = snapshot
                if converged(snapshot, args.expected_uid, args.replicas, convergence=args.convergence):
                    break
                time.sleep(min(1, max(0, deadline - time.monotonic())))
            report['outcome'] = 'workload_scaled'
    except Exception as error:
        # Do not leak arbitrary kubectl diagnostic strings or raw Pod env/Secret data.
        report['error_type'] = type(error).__name__
    print(json.dumps(report, sort_keys=True))
    return 0 if report['outcome'] in ('workload_observed', 'workload_scaled') else 1


if __name__ == '__main__':
    raise SystemExit(main())
