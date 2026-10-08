"""Private, bounded full-bucket listing semantics; never a privacy verdict.

The returned items/markers are operator-private inputs for ACL reads, not evidence.
Protocol: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html
Only general-purpose, unfiltered bucket listings with URL encoding are supported.
"""
import hashlib
import json
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET


class InventoryIncomplete(Exception):
    """Listing unavailable, ambiguous, inconsistent or outside its declared bounds."""


def bounded(value, limit, *, empty=False):
    if (not isinstance(value, str) or not (empty or value) or '\x00' in value
            or len(value.encode('utf-8')) > limit):
        raise InventoryIncomplete('Invalid private listing scalar')
    return value


def decoded(value, *, empty=False):
    bounded(value, 4096, empty=empty)
    if re.search(r'%(?![0-9a-fA-F]{2})', value):
        raise InventoryIncomplete('Ambiguous URL-encoded listing key')
    try:
        result = urllib.parse.unquote_to_bytes(value).decode('utf-8')
    except UnicodeError:
        raise InventoryIncomplete('Invalid listing key encoding') from None
    return bounded(result, 1024, empty=empty)


def parse_page(status, raw, *, bucket, kind, marker=None, page_size=100):
    """Validate one unfiltered page and request echoes, retaining private identities."""
    if (kind not in ('current', 'history') or type(page_size) is not int
            or not 1 <= page_size <= 1000 or type(status) is not int or status != 200
            or not isinstance(raw, bytes) or len(raw) > 1024 * 1024):
        raise InventoryIncomplete('Bounded available listing required')
    if marker is not None:
        if kind == 'current':
            bounded(marker, 4096)
        else:
            if not isinstance(marker, tuple) or len(marker) != 2:
                raise InventoryIncomplete('Invalid history marker')
            bounded(marker[0], 1024);bounded(marker[1], 1024)
    try:
        text = raw.decode('utf-8')
        if '<!DOCTYPE' in text or '<!ENTITY' in text:
            raise InventoryIncomplete('Listing declarations refused')
        root = ET.fromstring(text)
        prefix = '{http://s3.amazonaws.com/doc/2006-03-01/}' if root.tag.startswith('{') else ''
        expected = 'ListBucketResult' if kind == 'current' else 'ListVersionsResult'
        if root.tag != prefix + expected or root.attrib or len(list(root.iter())) > 12000:
            raise InventoryIncomplete('Unsupported listing schema')
        fields, entries = {}, []
        common = {'Name', 'Prefix', 'Delimiter', 'MaxKeys', 'IsTruncated', 'EncodingType'}
        allowed = common | ({'KeyCount', 'ContinuationToken', 'NextContinuationToken', 'StartAfter'}
                            if kind == 'current' else
                            {'KeyMarker', 'VersionIdMarker', 'NextKeyMarker', 'NextVersionIdMarker'})
        entry_names = {'Contents'} if kind == 'current' else {'Version', 'DeleteMarker'}

        def name(node):
            if not node.tag.startswith(prefix) or prefix and node.tag[len(prefix):].startswith('{'):
                raise InventoryIncomplete('Mixed listing namespaces')
            value = node.tag[len(prefix):]
            if '{' in value or '}' in value:
                raise InventoryIncomplete('Mixed listing namespaces')
            return value

        def scalar(node):
            if node.attrib or len(node):
                raise InventoryIncomplete('Ambiguous listing scalar')
            return bounded(node.text or '', 4096, empty=True)

        def boolean(value):
            if value not in ('true', 'false'):
                raise InventoryIncomplete('Invalid listing boolean')
            return value == 'true'

        if root.text and root.text.strip():
            raise InventoryIncomplete('Unexpected listing text')
        for node in root:
            field = name(node)
            if node.tail and node.tail.strip():
                raise InventoryIncomplete('Unexpected listing text')
            if field in entry_names:
                entries.append((field, node))
            elif field in allowed and field not in fields:
                fields[field] = scalar(node)
            else:
                raise InventoryIncomplete('Unknown or duplicate listing field')
        if (not {'Name', 'Prefix', 'MaxKeys', 'IsTruncated', 'EncodingType'} <= fields.keys()
                or fields['Name'] != bucket or fields['Prefix'] != ''
                or fields.get('Delimiter', '') or fields.get('StartAfter', '')
                or fields['MaxKeys'] != str(page_size) or fields['EncodingType'] != 'url'
                or len(entries) > page_size):
            raise InventoryIncomplete('Listing scope or size mismatch')
        truncated = boolean(fields['IsTruncated'])
        if kind == 'current':
            if fields.get('KeyCount') != str(len(entries)) or fields.get('ContinuationToken', '') != (marker or ''):
                raise InventoryIncomplete('Current listing count or continuation mismatch')
            next_marker = fields.get('NextContinuationToken') or None
            if next_marker is not None:
                bounded(next_marker, 4096)
        else:
            echoed = (decoded(fields.get('KeyMarker', ''), empty=True), fields.get('VersionIdMarker', ''))
            if echoed != (marker or ('', '')):
                raise InventoryIncomplete('History listing continuation mismatch')
            next_key = fields.get('NextKeyMarker', '')
            next_version = fields.get('NextVersionIdMarker', '')
            next_marker = ((decoded(next_key), bounded(next_version, 1024))
                           if next_key and next_version else None)
            if bool(next_key) != bool(next_version):
                raise InventoryIncomplete('Incomplete history continuation')
        if truncated != (next_marker is not None) or truncated and not entries:
            raise InventoryIncomplete('Incomplete or unexpected listing continuation')
        items = []
        for entry_kind, node in entries:
            if node.attrib or node.text and node.text.strip():
                raise InventoryIncomplete('Unsupported listing entry')
            identity = {}
            metadata = {'LastModified', 'ETag', 'Size', 'StorageClass', 'Owner',
                        'ChecksumAlgorithm', 'ChecksumType', 'RestoreStatus'}
            seen = set()
            for child in node:
                field = name(child)
                if child.tail and child.tail.strip() or field in seen and field != 'ChecksumAlgorithm':
                    raise InventoryIncomplete('Ambiguous listing entry')
                seen.add(field)
                if field in ('Key', 'VersionId', 'IsLatest'):
                    identity[field] = scalar(child)
                elif field not in metadata:
                    raise InventoryIncomplete('Unknown listing entry field')
                elif field in ('Owner', 'RestoreStatus'):
                    permitted = {'ID', 'DisplayName'} if field == 'Owner' else {'IsRestoreInProgress', 'RestoreExpiryDate'}
                    nested = set()
                    if child.attrib or child.text and child.text.strip():
                        raise InventoryIncomplete('Ambiguous listing metadata')
                    for part in child:
                        part_name = name(part)
                        if (part_name not in permitted or part_name in nested
                                or part.tail and part.tail.strip()):
                            raise InventoryIncomplete('Unknown listing metadata')
                        nested.add(part_name);scalar(part)
                else:
                    scalar(child)
            required = {'Key'} if kind == 'current' else {'Key', 'VersionId', 'IsLatest'}
            if set(identity) != required:
                raise InventoryIncomplete('Missing or extra listing identity')
            items.append(dict(key=decoded(identity['Key']),
                              version_id=None if kind == 'current' else bounded(identity['VersionId'], 1024),
                              latest=True if kind == 'current' else boolean(identity['IsLatest']),
                              delete_marker=entry_kind == 'DeleteMarker'))
        return dict(items=items, next_marker=next_marker)
    except (UnicodeError, ET.ParseError):
        raise InventoryIncomplete('Invalid listing XML') from None


def enumerate_inventory(fetch, *, bucket, kind, page_size=100, max_pages=20,
                        max_entries=1000, timeout=30):
    """Fetch all pages or raise. A terminal page is required; no partial success."""
    if (not callable(fetch) or kind not in ('current', 'history')
            or type(page_size) is not int or not 1 <= page_size <= 1000
            or type(max_pages) is not int or not 1 <= max_pages <= 32
            or type(max_entries) is not int or not 1 <= max_entries <= 10000
            or type(timeout) not in (int, float) or not 0 < timeout <= 60):
        raise ValueError('Bounded independently bound inventory transport required')
    started, wall_started = time.monotonic(), time.time()
    marker, markers, identities, latest, items = None, set(), set(), {}, []
    last_key = None
    for page_number in range(1, max_pages + 1):
        if max(time.monotonic() - started, time.time() - wall_started) >= timeout:
            raise InventoryIncomplete('Inventory deadline')
        status, raw = fetch(kind, marker, page_size)
        if max(time.monotonic() - started, time.time() - wall_started) >= timeout:
            raise InventoryIncomplete('Inventory deadline')
        page = parse_page(status, raw, bucket=bucket, kind=kind, marker=marker, page_size=page_size)
        for item in page['items']:
            key = item['key'].encode('utf-8')
            identity = (item['key'], item['version_id'])
            if identity in identities or kind == 'current' and last_key is not None and key <= last_key:
                raise InventoryIncomplete('Duplicate or unordered inventory identity')
            identities.add(identity);last_key = key
            latest[item['key']] = latest.get(item['key'], 0) + int(item['latest'])
            items.append(item)
            if len(items) > max_entries:
                raise InventoryIncomplete('Inventory entry limit')
        marker = page['next_marker']
        if marker is None:
            if any(count != 1 for count in latest.values()):
                raise InventoryIncomplete('Ambiguous latest inventory version')
            items.sort(key=lambda item: (item['key'].encode('utf-8'), item['version_id'] or '', item['delete_marker']))
            digest = hashlib.sha256(json.dumps(items, sort_keys=True, ensure_ascii=True,
                                               separators=(',', ':')).encode()).hexdigest()
            return dict(items=items, kind=kind, page_count=page_number, complete=True, sha256=digest)
        if marker in markers:
            raise InventoryIncomplete('Repeated inventory continuation')
        markers.add(marker)
    raise InventoryIncomplete('Inventory page limit')


def summarize_inventory(current, history):
    """Compare two internally collected private views; return only counts/digests.

    This does not create an atomic snapshot, fence writers, observe ACLs or bind
    the bucket to an application. Callers must retain those evidence limits.
    """
    for value, kind in ((current, 'current'), (history, 'history')):
        if value.get('kind') != kind or value.get('complete') is not True:
            raise InventoryIncomplete('Complete current and history views required')
    visible = {item['key'] for item in current['items']}
    retained_visible = {item['key'] for item in history['items'] if item['latest'] and not item['delete_marker']}
    if visible != retained_visible:
        raise InventoryIncomplete('Current and history views disagree')
    return dict(current_object_count=len(current['items']),
                retained_version_count=sum(not item['delete_marker'] for item in history['items']),
                delete_marker_count=sum(item['delete_marker'] for item in history['items']),
                current_sha256=current['sha256'], history_sha256=history['sha256'],
                current_page_count=current['page_count'], history_page_count=history['page_count'],
                listing_complete=True, current_history_consistent=True,
                privacy_verified=None, atomic_snapshot_verified=False)
