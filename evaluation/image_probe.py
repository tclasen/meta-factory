"""Standalone sandbox-side Kubernetes image identity probe; no raw Pod/env dump."""

import argparse
import json
import re
import subprocess
import sys


DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
REFERENCE = re.compile(r'[A-Za-z0-9._:/-]+(?:@sha256:[0-9a-f]{64})?')
NAME = re.compile(r'[a-z0-9][a-z0-9.-]*')


def inventory(pods):
    items = pods.get('items')
    if not isinstance(items, list) or len(items) > 1000:
        raise ValueError('Invalid or oversized Pod collection')
    result = []
    seen = set()
    for pod in items:
        metadata = pod['metadata']
        namespace, name = metadata['namespace'], metadata['name']
        if not NAME.fullmatch(namespace) or not NAME.fullmatch(name):
            raise ValueError('Invalid Pod identity')
        if (namespace, name) in seen:
            raise ValueError('Duplicate Pod identity')
        seen.add((namespace, name))
        for kind, field, status_field in [('application', 'containers', 'containerStatuses'),
                                          ('init', 'initContainers', 'initContainerStatuses'),
                                          ('ephemeral', 'ephemeralContainers', 'ephemeralContainerStatuses')]:
            statuses = pod.get('status', {}).get(status_field, [])
            if len({status['name'] for status in statuses}) != len(statuses):
                raise ValueError('Duplicate container status')
            by_name = {status['name']: status for status in statuses}
            for container in pod['spec'].get(field, []):
                reference = container['image']
                container_name = container['name']
                if (not NAME.fullmatch(container_name) or not REFERENCE.fullmatch(reference)
                        or '://' in reference):
                    raise ValueError('Unsafe image reference or container identity')
                status = by_name.get(container_name)
                if status is None or not status.get('imageID'):
                    raise ValueError('Container has no observed image identity')
                reported = status['imageID']
                bare = reported
                for prefix in ('docker-pullable://', 'containerd://', 'docker://'):
                    if bare.startswith(prefix):
                        bare = bare.removeprefix(prefix)
                        break
                digest = bare.rsplit('@', 1)[-1]
                if not DIGEST.fullmatch(digest) or (bare != digest and not REFERENCE.fullmatch(bare)):
                    raise ValueError('Unrecognized runtime image identity')
                result.append({'namespace': namespace, 'pod': name, 'container': container_name,
                               'kind': kind, 'declared_reference': reference,
                               'runtime_image_id': reported, 'runtime_digest': digest,
                               'reference_uses_digest': '@sha256:' in reference})
    if not result:
        raise ValueError('No live container image identities observed')
    return sorted(result, key=lambda item: (item['namespace'], item['pod'], item['kind'], item['container']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubectl-prefix', required=True, help='JSON argv inside the grading sandbox')
    parser.add_argument('--namespace', required=True)
    args = parser.parse_args()
    report = {'outcome': 'image_inventory_incomplete'}
    try:
        prefix = json.loads(args.kubectl_prefix)
        if (not isinstance(prefix, list) or not 1 <= len(prefix) <= 16
                or not all(isinstance(arg, str) and 0 < len(arg) <= 1024 for arg in prefix)
                or not NAME.fullmatch(args.namespace)):
            raise ValueError('Invalid sandbox query configuration')
        # Raw Kubernetes stdout/stderr stays in this bounded sandbox-side process.
        # Never send environment variables, Secret data or diagnostics to host logs.
        query = subprocess.run([*prefix, '-n', args.namespace, 'get', 'pods', '-o', 'json'],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        report['query_exit_code'] = query.returncode
        if query.returncode != 0:
            raise RuntimeError('Kubernetes image query failed')
        if len(query.stdout) > 16 * 1024 * 1024:
            raise ValueError('Kubernetes response exceeds image probe limit')
        records = inventory(json.loads(query.stdout))
        if any(record['namespace'] != args.namespace for record in records):
            raise ValueError('Kubernetes query returned a different namespace')
        report.update(outcome='image_identities_observed', images=records,
                      limits='Runtime-reported image IDs, not independent registry attestations or archived image layers')
    except Exception as error:
        report['error_type'] = type(error).__name__
    print(json.dumps(report, sort_keys=True))
    return 0 if report['outcome'] == 'image_identities_observed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
