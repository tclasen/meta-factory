"""Compose one explicitly supported operator-built MinIO provider snapshot."""
import hashlib
import json
import sys


PROFILE = 'minio-fixture-2025-04-22-arm64-cgo0-v1'
EXECUTABLE = 'c6898f3c2ca26957848ddf33e314c7111928b1ae0c91f02281e981293fddd8cc'
SOURCE_ARCHIVE = '1a63209927b9d1fb239b2a776b7b01d1902eff19379a108f4bc7005edcc0968c'
# Protected operator build evidence binds this archive, CGO_ENABLED=0 and binary.
# Source policy getter is shared by GET policy and anonymous authorization;
# absent policy returns owner-only permission; ACL handlers do not store ACLs.


def main(signing, policy, listener, route):
    report = dict(outcome='storage_observation_incomplete', private_anonymous_verified=None,
                  read_write_checked=False, cleanup_verified=None, abort_suite=True,
                  provider_snapshot_stable=False, policy_snapshot_stable=False,
                  direct_route_verified=False, atomic_snapshot_verified=False,
                  credential_exposure_verified=False, future_changes_verified=False)
    try:
        if sys.argv[2] != PROFILE:raise ValueError('Unsupported provider profile')
        config = signing['private_binding'](sys.argv[1])
        pid, start = int(sys.argv[3]), sys.argv[4]
        parsed = signing['urllib'].parse.urlsplit(config['endpoint'])
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        identity = listener['observe'](pid, start, EXECUTABLE, parsed.hostname, port)
        if not identity['same_network_namespace']:raise ValueError('Direct provider namespace required')
        before_route = route['observe_route'](config, pid, listener, signing)
        peer = signing['Peer'](config)
        def read_policy():
            peer.check(5)
            path = '/' + config['bucket'];query = 'policy='
            timestamp = signing['datetime'].now(signing['timezone'].utc).strftime('%Y%m%dT%H%M%SZ')
            headers = signing['signed_headers'](config, 'GET', path, query, b'', timestamp)
            request = signing['urllib'].request.Request(config['endpoint'] + path + '?' + query,
                                                       headers=headers, method='GET')
            try:response = peer.opener.open(request, timeout=5)
            except signing['urllib'].error.HTTPError as error:response = error
            with response:status = response.status;raw = response.read(65537)
            peer.check()
            classified = policy['classify_response'](status, raw, config['bucket'])
            digest = hashlib.sha256(b'NoSuchBucketPolicy' if status == 404 else raw).hexdigest()
            return classified, digest
        before_policy = read_policy()
        canary = signing['observe'](config)
        report.update(canary_outcome=canary['outcome'], canary_key=canary['key'], canary_versions=canary['versions'],
                      read_write_checked=canary['read_write_checked'], cleanup_verified=canary['cleanup_verified'])
        after_policy = read_policy()
        after_route = route['observe_route'](config, pid, listener, signing)
        after_identity = listener['observe'](pid, start, EXECUTABLE, parsed.hostname, port)
        if config != signing['private_binding'](sys.argv[1]):raise ValueError('Provider binding changed')
        provider_stable = identity == after_identity
        policy_stable = before_policy == after_policy
        direct = all(value['pid'] == pid and value['address'] == str(signing['ipaddress'].ip_address(parsed.hostname))
                     and value['port'] == port and value['net_namespace_device'] == identity['net_namespace_device']
                     and value['net_namespace_inode'] == identity['net_namespace_inode']
                     for value in (before_route, after_route))
        report.update(bucket=config['bucket'], provider_profile=PROFILE, executable_sha256=EXECUTABLE,
                      source_archive_sha256=SOURCE_ARCHIVE, provider_snapshot_stable=provider_stable,
                      policy_snapshot_stable=policy_stable, direct_route_verified=direct,
                      policy_classification=before_policy[0]['classification'], policy_sha256=before_policy[1],
                      provider_identity_sha256=hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest())
        if not provider_stable or not policy_stable or not direct or not canary['cleanup_verified']:
            return
        classification = before_policy[0]['classification']
        private = None
        if classification in ('bucket_policy_absent', 'no_broad_grant_in_supported_policy'):
            if canary['anonymous_read_denied'] and canary['anonymous_write_denied']:private = True
        elif classification == 'unconditional_broad_grant_observed':private = False
        report['private_anonymous_verified'] = private
        if private is not None:
            report.update(outcome='storage_provider_observed', abort_suite=not (
                private and canary['outcome'] == 'pass' and canary['read_write_checked']))
    except BaseException as error:report['error_type'] = type(error).__name__
    finally:print(json.dumps(report, allow_nan=False))
