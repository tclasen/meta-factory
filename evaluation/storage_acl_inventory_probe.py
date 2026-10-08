"""Trusted read-only inventory-wide ACL peer; raw identities stay private."""
import hashlib
import json
import os
import stat
import sys


def read_manifest(path, expected_hash, private_parent):
    parent, name, parent_identity = private_parent(path)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o077
                    or before.st_size > 8 * 1024 * 1024):
                raise ValueError('Private manifest required')
            raw = stream.read(8 * 1024 * 1024 + 1)
            after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (len(raw) > 8 * 1024 * 1024 or any(getattr(before, key) != getattr(after, key)
                or getattr(after, key) != getattr(named, key) for key in fields)
                or hashlib.sha256(raw).hexdigest() != expected_hash):
            raise ValueError('Private manifest changed')
        reopened, _, after_parent_identity = private_parent(path)
        os.close(reopened)
        if parent_identity != after_parent_identity:
            raise ValueError('Private manifest directory changed')
        return raw, (parent_identity, tuple(getattr(after, key) for key in fields))
    finally:os.close(parent)


def main(support, inventory, private_files, semantics, core):
    report = dict(outcome='acl_inventory_observation_incomplete', classification='inconclusive')
    try:
        config = support['private_binding'](sys.argv[1])
        raw, manifest_identity = read_manifest(sys.argv[2], sys.argv[3], private_files['private_parent'])
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:raise ValueError('Duplicate manifest field')
                result[key] = value
            return result
        def constant(_):raise ValueError('Nonfinite manifest value')
        manifest = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(manifest, dict) or manifest.get('bucket') != config['bucket']:
            raise ValueError('Manifest bucket mismatch')
        size = int(sys.argv[4])
        if not 1 <= size <= 1000:raise ValueError('Bounded inventory page size required')
        peer = support['Peer'](config)

        def request(path, query, limit):
            peer.check(5)
            timestamp = support['datetime'].now(support['timezone'].utc).strftime('%Y%m%dT%H%M%SZ')
            headers = support['signed_headers'](config, 'GET', path, query, b'', timestamp)
            req = support['urllib'].request.Request(config['endpoint'] + path + '?' + query,
                                                   headers=headers, method='GET')
            try:response = peer.opener.open(req, timeout=5)
            except support['urllib'].error.HTTPError as error:response = error
            with response:status = response.status;body = response.read(limit + 1)
            peer.check()
            return status, body

        def fetch_inventory(kind, marker, page_size):
            params = {'encoding-type': 'url', 'max-keys': str(page_size)}
            if kind == 'current':
                params['list-type'] = '2'
                if marker is not None:params['continuation-token'] = marker
            else:
                params['versions'] = ''
                if marker is not None:
                    params.update({'key-marker': marker[0], 'version-id-marker': marker[1]})
            query = support['urllib'].parse.urlencode(sorted(params.items()),
                        quote_via=support['urllib'].parse.quote, safe='')
            return request('/' + config['bucket'], query, 1024 * 1024)

        def inventory_check(expected):
            views = {kind:inventory['enumerate_inventory'](fetch_inventory, bucket=config['bucket'],
                     kind=kind, page_size=size, timeout=12) for kind in ('current', 'history')}
            inventory['summarize_inventory'](views['current'], views['history'])
            return all(views[kind]['sha256'] == expected[kind]['sha256'] for kind in views)

        def fetch_acl(kind, key, version):
            path = '/' + config['bucket'] + ('' if key is None else '/' + support['urllib'].parse.quote(key, safe='/'))
            query = 'acl=' + ('' if version is None else '&versionId=' + support['urllib'].parse.quote(version, safe=''))
            return request(path, query, 65536)

        result = core['scan_acl_inventory'](manifest, fetch_acl=fetch_acl, inventory_check=inventory_check,
                                           classify_acl=semantics['classify_acl'])
        _, after_identity = read_manifest(sys.argv[2], sys.argv[3], private_files['private_parent'])
        if manifest_identity != after_identity:raise ValueError('Manifest changed during scan')
        peer.check()
        report.update(result, outcome='acl_inventory_observed', bucket=config['bucket'],
                      inventory_manifest_sha256=sys.argv[3], manifest_stable=True)
    except BaseException as error:report['error_type'] = type(error).__name__
    print(json.dumps(report, allow_nan=False))
