"""Trusted peer for a scoped private S3 canary; no credential diagnostics.

SigV4 canonicalization follows the S3 single-chunk header protocol:
https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
This peer runs in the owned grading environment, never on the builder or host.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class ObservationIncomplete(Exception):
    pass


class ObservationFailure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def private_binding(path):
    absolute = Path(os.path.abspath(path))
    parent = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        descriptor = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & 0o077 or before.st_size > 16384):
            raise ObservationIncomplete('Private ordinary binding required')
        raw = stream.read(16385)
        after = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ObservationIncomplete('Private binding changed')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:raise ObservationIncomplete('Duplicate binding field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    validate_binding(value)
    return value


def validate_binding(value):
    if (not isinstance(value, dict) or set(value) != {'endpoint', 'bucket', 'region',
                                                   'access_key', 'secret_key', 'session_token'}
            or any(not isinstance(value[k], str) or not value[k] or len(value[k]) > 4096
                   or any(ord(c) < 32 or ord(c) > 126 for c in value[k])
                   for k in ('endpoint', 'bucket', 'region', 'access_key', 'secret_key'))
            or value['session_token'] is not None and (not isinstance(value['session_token'], str)
                or not value['session_token'] or len(value['session_token']) > 4096
                or any(ord(c) < 32 or ord(c) > 126 for c in value['session_token']))):
        raise ObservationIncomplete('Complete private binding required')
    if (not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', value['bucket'])
            or '..' in value['bucket'] or '.-' in value['bucket'] or '-.' in value['bucket']
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', value['region'])):
        raise ObservationIncomplete('Bounded bucket/region required')
    parsed = urllib.parse.urlsplit(value['endpoint'])
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
            or parsed.password or parsed.path or parsed.query or parsed.fragment
            or not parsed.port or not 1 <= parsed.port <= 65535
            or value['endpoint'] != parsed.scheme + '://' + parsed.netloc):
        raise ObservationIncomplete('Exact internal origin required')
    try:
        address = ipaddress.ip_address(parsed.hostname)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        internal = (address.is_loopback or address.is_private) and not (
            address.is_link_local or address.is_multicast or address.is_unspecified)
    except ValueError:
        internal = bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.incident-app\.svc(?:\.cluster\.local)?',
                                     parsed.hostname))
    if not internal:raise ObservationIncomplete('Only independently bound internal storage allowed')
    return value


def signed_headers(config, method, path, query, body, timestamp):
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {'host': urllib.parse.urlsplit(config['endpoint']).netloc,
               'x-amz-content-sha256': payload_hash, 'x-amz-date': timestamp}
    if config['session_token'] is not None:headers['x-amz-security-token'] = config['session_token']
    names = ';'.join(sorted(headers))
    canonical = '\n'.join((method, path, query,
        ''.join(key + ':' + headers[key].strip() + '\n' for key in sorted(headers)), names, payload_hash))
    scope = timestamp[:8] + '/' + config['region'] + '/s3/aws4_request'
    message = '\n'.join(('AWS4-HMAC-SHA256', timestamp, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()))
    key = ('AWS4' + config['secret_key']).encode()
    for part in (timestamp[:8], config['region'], 's3', 'aws4_request'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    headers['authorization'] = ('AWS4-HMAC-SHA256 Credential=' + config['access_key'] + '/' + scope
                                + ',SignedHeaders=' + names + ',Signature=' + signature)
    return headers


class Peer:
    def __init__(self, config):
        self.config = validate_binding(config)
        self.started, self.wall_started = time.monotonic(), time.time()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def check(self, reserve=0):
        monotonic = time.monotonic() - self.started
        wall = time.time() - self.wall_started
        if abs(monotonic - wall) > 5 or max(monotonic, wall) + reserve >= 70:
            raise ObservationIncomplete('Storage observation lifetime unavailable')

    def request(self, method, key=None, *, body=b'', signed=True, version=None):
        if (method not in ('HEAD', 'GET', 'PUT', 'DELETE')
                or key is None and method != 'HEAD'
                or key is not None and not re.fullmatch(r'factory-evaluation-canary/[0-9a-f]{32}', key)
                or version is not None and method != 'DELETE'):
            raise ObservationIncomplete('Only exact owned canary operations allowed')
        self.check(5)
        path = '/' + self.config['bucket']
        if key is not None:path += '/' + urllib.parse.quote(key, safe='/')
        query = '' if version is None else 'versionId=' + urllib.parse.quote(version, safe='')
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        headers = signed_headers(self.config, method, path, query, body, timestamp) if signed else {}
        request = urllib.request.Request(self.config['endpoint'] + path + ('?' + query if query else ''),
            data=body if method == 'PUT' else None, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.status
            content = response.read(4097)
            version_id = response.headers.get('x-amz-version-id')
        if len(content) > 4096 or (version_id is not None and (
                not version_id or len(version_id) > 1024 or any(ord(c) < 32 for c in version_id))):
            raise ObservationIncomplete('Storage response bound exceeded')
        self.check()
        return status, content, version_id


def observe(config):
    peer = Peer(config)
    key = 'factory-evaluation-canary/' + uuid.uuid4().hex
    body = os.urandom(512)
    report = dict(outcome='inconclusive', bucket=config['bucket'], key=key,
                  read_write_checked=False, anonymous_read_denied=False,
                  anonymous_write_denied=False, cleanup_verified=False, versions=[])
    owned = False
    try:
        if peer.request('HEAD')[0] != 200:raise ObservationIncomplete('Bound bucket unavailable')
        if peer.request('HEAD', key)[0] != 404:raise ObservationIncomplete('Fresh object key unavailable')
        owned = True
        peer.check(25)
        status, _, version = peer.request('PUT', key, body=body)
        if version is not None:report['versions'].append(version)
        if status not in (200, 201):raise ObservationIncomplete('Authenticated write unavailable')
        status, observed, _ = peer.request('GET', key)
        if status != 200:raise ObservationIncomplete('Authenticated read unavailable')
        if observed != body:raise ObservationFailure('Authenticated read differs')
        report['read_write_checked'] = True
        peer.check(20)
        status, _, _ = peer.request('GET', key, signed=False)
        if status == 200:raise ObservationFailure('Anonymous read allowed')
        if status not in (401, 403, 404):raise ObservationIncomplete('Anonymous read denial unavailable')
        report['anonymous_read_denied'] = True
        status, _, version = peer.request('PUT', key, signed=False, body=body[::-1])
        if version is not None and version not in report['versions']:report['versions'].append(version)
        if status in (200, 201):raise ObservationFailure('Anonymous write allowed')
        if status not in (401, 403, 404):raise ObservationIncomplete('Anonymous write denial unavailable')
        status, observed, _ = peer.request('GET', key)
        if status != 200:raise ObservationIncomplete('Post-denial authenticated read unavailable')
        report['anonymous_write_denied'] = observed == body
        report['outcome'] = 'pass' if observed == body else 'fail'
    except ObservationFailure:
        report['outcome'] = 'fail'
    except BaseException as error:
        report.update(outcome='inconclusive', error_type=type(error).__name__)
    finally:
        if owned:
            try:
                # Remove every version disclosed by our own writes; no bucket/list
                # deletion or guessed versions. Unknown historical versions are
                # outside this bounded canary's claims.
                for version in report['versions']:
                    if peer.request('DELETE', key, version=version)[0] not in (200, 204):
                        raise ObservationIncomplete('Owned version cleanup unavailable')
                # Explicit version deletion must not create a new delete marker.
                if not report['versions'] and peer.request('DELETE', key)[0] not in (200, 204):
                    raise ObservationIncomplete('Owned object cleanup unavailable')
                report['cleanup_verified'] = peer.request('HEAD', key)[0] == 404
            except BaseException as error:
                report['cleanup_error_type'] = type(error).__name__
            if not report['cleanup_verified']:report['outcome'] = 'cleanup_incomplete'
    report['abort_suite'] = report['outcome'] != 'pass'
    return report


def main():
    try:
        report = observe(private_binding(sys.argv[1]))
    except BaseException as error:
        report = dict(outcome='inconclusive', error_type=type(error).__name__,
                      cleanup_verified=False, abort_suite=True)
    # The report contains no body, signing headers, endpoint, credential values
    # or exception messages. The owned key/version list allows exact cleanup.
    print(json.dumps(report, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
