"""Trusted peer body composed with signing and inventory namespaces by the controller."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def private_parent(path):
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor);descriptor = child
        identity = os.fstat(descriptor)
        if identity.st_mode & 0o077:
            raise ValueError('Private output directory required')
        return descriptor, absolute.name, (identity.st_dev, identity.st_ino, identity.st_uid, identity.st_mode)
    except BaseException:
        os.close(descriptor)
        raise


def main(support, inventory):
    report = dict(outcome='inventory_observation_incomplete', snapshot_stable=False,
                  private_manifest_written=False)
    parent = None
    try:
        config = support['private_binding'](sys.argv[1])
        size = int(sys.argv[3])
        if not 1 <= size <= 1000:
            raise ValueError('Bounded inventory page size required')
        parent, name, identity = private_parent(sys.argv[2])
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('Exclusive new private manifest required')
        peer = support['Peer'](config)

        def fetch(kind, marker, page_size):
            peer.check(5)
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
            path = '/' + config['bucket']
            timestamp = support['datetime'].now(support['timezone'].utc).strftime('%Y%m%dT%H%M%SZ')
            headers = support['signed_headers'](config, 'GET', path, query, b'', timestamp)
            request = support['urllib'].request.Request(config['endpoint'] + path + '?' + query,
                                                       headers=headers, method='GET')
            try:response = peer.opener.open(request, timeout=5)
            except support['urllib'].error.HTTPError as error:response = error
            with response:status = response.status;raw = response.read(1024 * 1024 + 1)
            peer.check()
            return status, raw

        views = []
        for _ in range(2):
            current = inventory['enumerate_inventory'](fetch, bucket=config['bucket'], kind='current',
                                                        page_size=size, timeout=12)
            history = inventory['enumerate_inventory'](fetch, bucket=config['bucket'], kind='history',
                                                        page_size=size, timeout=12)
            summary = inventory['summarize_inventory'](current, history)
            views.append((current, history, summary))
        if views[0] != views[1]:
            raise ValueError('Inventory snapshots changed')
        reopened, _, after_identity = private_parent(sys.argv[2])
        os.close(reopened)
        if identity != after_identity:
            raise ValueError('Private output directory changed')
        payload = json.dumps(dict(bucket=config['bucket'], current=views[0][0], history=views[0][1]),
                             sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
        if len(payload) > 8 * 1024 * 1024:
            raise ValueError('Private manifest size exceeded')
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload);stream.flush();os.fsync(stream.fileno())
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
                raise ValueError('Private manifest identity changed')
        report.update(views[0][2], outcome='inventory_observed', bucket=config['bucket'],
                      snapshot_stable=True, private_manifest_written=True,
                      private_manifest_sha256=hashlib.sha256(payload).hexdigest())
    except BaseException as error:
        report['error_type'] = type(error).__name__
    finally:
        if parent is not None:os.close(parent)
    print(json.dumps(report, allow_nan=False))
