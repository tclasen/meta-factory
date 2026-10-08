"""Bounded S3 ACL observations; declared grants are not effective authorization.

Schema and predefined groups:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
"""
import hashlib
import re
import xml.etree.ElementTree as ET


S3_NAMESPACE = 'http://s3.amazonaws.com/doc/2006-03-01/'
XSI_TYPE = '{http://www.w3.org/2001/XMLSchema-instance}type'
ANONYMOUS_ID = '65a011a29cdf8ec533ec3d1ccaae921c'
GROUP_BASE = 'http://acs.amazonaws.com/groups/'
PERMISSIONS = {'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'}


def classify_acl(status, raw):
    """Return counts/hashes only. Malformed, unavailable or unknown ACLs are inconclusive."""
    result = dict(classification='inconclusive', grant_count=0, broad_grant_count=0,
                  unsupported_grant_count=0, owner_sha256=None)
    if status != 200 or not isinstance(raw, bytes) or len(raw) > 65536:
        return result
    try:
        text = raw.decode('utf-8')
        if '<!DOCTYPE' in text or '<!ENTITY' in text:
            return result
        root = ET.fromstring(text)
        prefix = ('{' + S3_NAMESPACE + '}') if root.tag.startswith('{') else ''
        def tag(name):return prefix + name
        if root.tag != tag('AccessControlPolicy') or len(list(root.iter())) > 1024:
            return result

        def children(node, required, optional=()):
            if node.attrib or node.text and node.text.strip():
                raise ValueError('Unsupported ACL structure')
            fields = {}
            for child in node:
                if child.tag not in {tag(name) for name in (*required, *optional)}:
                    raise ValueError('Unknown ACL field')
                name = child.tag[len(prefix):]
                if name in fields or child.tail and child.tail.strip():
                    raise ValueError('Ambiguous ACL field')
                fields[name] = child
            if not set(required) <= fields.keys():
                raise ValueError('Missing ACL field')
            return fields

        def scalar(node):
            value = node.text or ''
            if node.attrib or len(node) or not 1 <= len(value) <= 2048:
                raise ValueError('Unsupported ACL scalar')
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError('Invalid ACL scalar')
            return value

        def canonical(node):
            value = scalar(node)
            if not re.fullmatch(r'[A-Za-z0-9._:@/-]{1,256}', value):
                raise ValueError('Unsupported canonical ID')
            return value

        def display_name(node):
            # S3-compatible peers may return an empty, optional display name.
            if node.text is None and not node.attrib and not len(node):
                return
            scalar(node)

        fields = children(root, ('Owner', 'AccessControlList'))
        owner = children(fields['Owner'], ('ID',), ('DisplayName',))
        owner_id = canonical(owner['ID'])
        if 'DisplayName' in owner:
            display_name(owner['DisplayName'])
        grants = fields['AccessControlList']
        if grants.attrib or grants.text and grants.text.strip() or not 1 <= len(grants) <= 100:
            return result
        if any(grant.tag != tag('Grant') or grant.tail and grant.tail.strip() for grant in grants):
            return result
        result['owner_sha256'] = hashlib.sha256(owner_id.encode()).hexdigest()
        result['grant_count'] = len(grants)
        for grant in grants:
            try:
                fields = children(grant, ('Grantee', 'Permission'))
                if scalar(fields['Permission']) not in PERMISSIONS:
                    raise ValueError('Unknown permission')
                grantee = fields['Grantee']
                if set(grantee.attrib) != {XSI_TYPE}:
                    raise ValueError('Unknown grantee type')
                kind = grantee.attrib[XSI_TYPE]
                # Validate the same strict structure without mutating the parsed ACL.
                copy = ET.Element(grantee.tag)
                copy.text = grantee.text
                copy.extend(list(grantee))
                if kind == 'CanonicalUser':
                    values = children(copy, ('ID',), ('DisplayName',))
                    identity = canonical(values['ID'])
                    if 'DisplayName' in values:
                        display_name(values['DisplayName'])
                    broad = identity == ANONYMOUS_ID
                elif kind == 'Group':
                    values = children(copy, ('URI',))
                    uri = scalar(values['URI'])
                    if uri not in {GROUP_BASE + 'global/AllUsers',
                                   GROUP_BASE + 'global/AuthenticatedUsers',
                                   GROUP_BASE + 's3/LogDelivery'}:
                        raise ValueError('Unknown group')
                    broad = uri != GROUP_BASE + 's3/LogDelivery'
                else:
                    raise ValueError('Unsupported grantee')
                result['broad_grant_count'] += int(broad)
            except ValueError:
                result['unsupported_grant_count'] += 1
        if not result['unsupported_grant_count']:
            result['classification'] = ('broad_acl_grant_observed' if result['broad_grant_count']
                                        else 'no_broad_grant_in_supported_acl')
    except (UnicodeError, ET.ParseError, ValueError):
        pass
    return result
