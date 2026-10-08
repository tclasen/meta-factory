"""Conservative bucket-policy observations, not full effective S3 authorization.

Principal/ACL semantics: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html
Explicit denies and other controls can override a declared Allow. Unknown layouts
remain inconclusive; policy absence alone cannot establish whole-bucket privacy.
"""
import json
import re
import xml.etree.ElementTree as ET


def unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:raise ValueError('Duplicate policy field')
        result[key] = value
    return result


def strings(value):
    values = [value] if isinstance(value, str) else value
    if (not isinstance(values, list) or not 1 <= len(values) <= 64
            or any(not isinstance(v, str) or not v or len(v) > 2048 for v in values)):
        raise ValueError('Bounded policy strings required')
    return values


def principal(value):
    if value == '*':return 'broad'
    if not isinstance(value, dict) or len(value) != 1:raise ValueError('Unsupported principal')
    kind = next(iter(value));values = strings(value[kind])
    if kind == 'AWS':
        if '*' in values:return 'broad'
        if all(re.fullmatch(r'(?:[0-9]{12}|arn:aws(?:-[a-z]+)?:iam::[0-9]{12}:(?:root|(?:user|role)/[A-Za-z0-9+=,.@_/-]+))',
                            v) for v in values):return 'fixed'
    if kind == 'CanonicalUser' and all(re.fullmatch(r'[0-9a-f]{64}', v) for v in values):return 'fixed'
    raise ValueError('Unsupported principal')


def classify_policy(value, bucket):
    result = dict(classification='inconclusive', statement_count=0, public_grant_count=0,
                  unsupported_statement_count=0, explicit_deny_present=False)
    if (not isinstance(value, dict) or not {'Version', 'Statement'} <= set(value)
            or not set(value) <= {'Version', 'Statement', 'Id'}
            or value['Version'] not in ('2008-10-17', '2012-10-17')
            or 'Id' in value and not isinstance(value['Id'], str)):
        return result
    statements = value['Statement']
    if isinstance(statements, dict):statements = [statements]
    if not isinstance(statements, list) or not 1 <= len(statements) <= 64:return result
    result['statement_count'] = len(statements)
    base = 'arn:aws:s3:::' + bucket
    for statement in statements:
        try:
            if (not isinstance(statement, dict) or not {'Effect', 'Principal', 'Action', 'Resource'} <= set(statement)
                    or not set(statement) <= {'Sid', 'Effect', 'Principal', 'Action', 'Resource'}
                    or statement['Effect'] not in ('Allow', 'Deny')
                    or 'Sid' in statement and not isinstance(statement['Sid'], str)):
                raise ValueError('Unsupported statement')
            who = principal(statement['Principal'])
            actions = strings(statement['Action']);resources = strings(statement['Resource'])
            known = {'s3:*', 's3:GetObject', 's3:GetObjectVersion', 's3:PutObject', 's3:DeleteObject',
                     's3:DeleteObjectVersion', 's3:ListBucket', 's3:ListBucketVersions',
                     's3:GetBucketAcl', 's3:PutBucketAcl', 's3:GetObjectAcl', 's3:PutObjectAcl'}
            if (any(action not in known for action in actions)
                    or any(resource != base and not resource.startswith(base + '/') for resource in resources)):
                raise ValueError('Unsupported action/resource')
            if statement['Effect'] == 'Deny':result['explicit_deny_present'] = True
            elif who == 'broad':result['public_grant_count'] += 1
        except (ValueError, KeyError, TypeError):
            result['unsupported_statement_count'] += 1
    if result['unsupported_statement_count']:return result
    if result['public_grant_count']:
        result['classification'] = ('inconclusive' if result['explicit_deny_present']
                                    else 'unconditional_broad_grant_observed')
    else:
        result['classification'] = 'no_broad_grant_in_supported_policy'
    return result


def classify_response(status, raw, bucket):
    if not isinstance(raw, bytes) or len(raw) > 65536:raise ValueError('Bounded policy response required')
    if status == 404:
        text = raw.decode('utf-8')
        if '<!DOCTYPE' in text or '<!ENTITY' in text:raise ValueError('Policy error declarations refused')
        tree = ET.fromstring(text)
        if tree.tag.rsplit('}', 1)[-1] != 'Error':raise ValueError('S3 policy error required')
        codes = [child.text for child in tree if child.tag.rsplit('}', 1)[-1] == 'Code']
        if codes != ['NoSuchBucketPolicy']:raise ValueError('Missing policy not independently observed')
        return dict(classification='bucket_policy_absent', statement_count=0, public_grant_count=0,
                    unsupported_statement_count=0, explicit_deny_present=False)
    if status != 200:raise ValueError('Policy read unavailable')
    return classify_policy(json.loads(raw, object_pairs_hook=unique_pairs), bucket)
