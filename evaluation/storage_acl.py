"""Guarded read-only ACL capture for one independently selected S3 resource."""
import hashlib
import json
from pathlib import Path
import re

from .evidence import atomic_json, collect
from .identity_observer import unique_pairs
from .job_storage import bucket_name
from .verdicts import Inconclusive


def probe_source():
    directory = Path(__file__).parent
    support = (directory / 'storage_canary_probe.py').read_text()
    semantics = (directory / 'storage_acl_semantics.py').read_text()
    prefix = ('import hashlib,json,sys,os,stat\n'
              'support={"__name__":"trusted_acl_signing"}\n'
              'exec(compile(' + repr(support) + ',"trusted-signing","exec"),support)\n'
              'semantics={"__name__":"trusted_acl_semantics"}\n'
              'exec(compile(' + repr(semantics) + ',"trusted-semantics","exec"),semantics)\n')
    return prefix + '''
report=dict(classification='inconclusive',snapshot_stable=False)
try:
 config=support['private_binding'](sys.argv[1]);peer=support['Peer'](config)
 path=support['Path'](os.path.abspath(sys.argv[2]))
 parent=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  for part in path.parts[1:-1]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   os.close(parent);parent=child
  descriptor=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
 finally:os.close(parent)
 with os.fdopen(descriptor,'rb') as stream:
  before=os.fstat(stream.fileno())
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_mode&0o077 or before.st_size>8192:
   raise ValueError('Private target required')
  raw=stream.read(8193);after=os.fstat(stream.fileno())
  if len(raw)>8192 or any(getattr(before,k)!=getattr(after,k) for k in
    ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):raise ValueError('Target changed')
 def pairs(items):
  result={}
  for key,value in items:
   if key in result:raise ValueError('Duplicate target field')
   result[key]=value
  return result
 target=json.loads(raw,object_pairs_hook=pairs)
 if not isinstance(target,dict) or set(target)!={'key','version_id'}:raise ValueError('Exact target required')
 key=target['key'];version=target['version_id']
 for value in (key,version):
  if value is not None and (not isinstance(value,str) or not 1<=len(value.encode('utf-8'))<=1024
    or any(ord(c)<32 or ord(c)==127 for c in value)):raise ValueError('Bounded target required')
 if key is None and version is not None:raise ValueError('Version requires object')
 if key is not None and any(part in ('.','..') for part in key.split('/')):
  raise ValueError('Ambiguous intermediary path refused')
 scope='bucket' if key is None else ('object' if version is None else 'version')
 target_hash=hashlib.sha256(json.dumps(target,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
 path='/'+config['bucket']+('' if key is None else '/'+support['urllib'].parse.quote(key,safe='/'))
 query='acl='+('' if version is None else '&versionId='+support['urllib'].parse.quote(version,safe=''))
 def read_acl():
  peer.check(5)
  timestamp=support['datetime'].now(support['timezone'].utc).strftime('%Y%m%dT%H%M%SZ')
  headers=support['signed_headers'](config,'GET',path,query,b'',timestamp)
  request=support['urllib'].request.Request(config['endpoint']+path+'?'+query,headers=headers,method='GET')
  try:response=peer.opener.open(request,timeout=5)
  except support['urllib'].error.HTTPError as error:response=error
  with response:status=response.status;raw=response.read(65537)
  peer.check()
  return semantics['classify_acl'](status,raw),hashlib.sha256(raw).hexdigest(),status
 first,before,status=read_acl();second,after,second_status=read_acl()
 report.update(first,bucket=config['bucket'],scope=scope,target_sha256=target_hash,
  acl_sha256=before,second_acl_sha256=after,status=status,second_status=second_status,
  snapshot_stable=before==after and status==second_status and first==second)
 if not report['snapshot_stable']:report['classification']='inconclusive'
except BaseException as error:report['error_type']=type(error).__name__
print(json.dumps(report,allow_nan=False))
'''


def capture_acl(attempt, *, peer_prefix, private_binding_path, private_target_path,
                lifetime_check, label='foundation-storage-acl'):
    """Caller binds peer identity, credentials, private target and lifetimes twice."""
    paths = (private_binding_path, private_target_path)
    if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
            or any(not isinstance(v, str) or not v or len(v) > 1024 or '\x00' in v for v in peer_prefix)
            or any(not isinstance(v, str) or not v.startswith('/') or len(v) > 4096
                   or '\x00' in v for v in paths)
            or not callable(lifetime_check) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)):
        raise ValueError('Bounded independently verified ACL peer required')
    if lifetime_check(35) is not True:
        raise Inconclusive('ACL peer lifetime unavailable')
    source = probe_source()
    command = collect(attempt, label, [*peer_prefix, 'python3', '-c', source, *paths],
                      cwd=Path(__file__).resolve().parents[1], timeout=30, max_output_bytes=8192)
    report = dict(outcome='acl_observation_incomplete', classification='inconclusive',
                  snapshot_stable=False, privacy_verified=None, inventory_complete=False,
                  command=command, probe_sha256=hashlib.sha256(source.encode()).hexdigest(),
                  limits='One selected declared ACL only. Complete bucket/object/version inventory, '
                         'other authorization controls and concurrent unseen changes remain unverified. '
                         'No whole-bucket privacy or AC-001 acceptance verdict.')
    try:
        value = json.loads((attempt.directory / label / 'stdout.log').read_text(),
                           object_pairs_hook=unique_pairs)
        fields = {'classification', 'snapshot_stable', 'bucket', 'scope', 'target_sha256',
                  'acl_sha256', 'second_acl_sha256', 'status', 'second_status', 'owner_sha256',
                  'grant_count', 'broad_grant_count', 'unsupported_grant_count'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['classification'] not in ('inconclusive', 'broad_acl_grant_observed',
                                                   'no_broad_grant_in_supported_acl')
                or type(value['snapshot_stable']) is not bool
                or value['scope'] not in ('bucket', 'object', 'version')
                or any(type(value[k]) is not int or not 100 <= value[k] <= 599
                       for k in ('status', 'second_status'))
                or any(type(value[k]) is not int or not 0 <= value[k] <= 100
                       for k in ('grant_count', 'broad_grant_count', 'unsupported_grant_count'))
                or value['broad_grant_count'] + value['unsupported_grant_count'] > value['grant_count']
                or any(not isinstance(value[k], str) or not re.fullmatch(r'[0-9a-f]{64}', value[k])
                       for k in ('target_sha256', 'acl_sha256', 'second_acl_sha256'))
                or value['owner_sha256'] is not None and (not isinstance(value['owner_sha256'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', value['owner_sha256']))
                or value['snapshot_stable'] and (value['acl_sha256'] != value['second_acl_sha256']
                                                or value['status'] != value['second_status'])
                or not value['snapshot_stable'] and value['classification'] != 'inconclusive'
                or value['classification'] != 'inconclusive' and (
                    value['status'] != 200 or value['second_status'] != 200
                    or value['unsupported_grant_count'] or not value['grant_count']
                    or value['owner_sha256'] is None)
                or value['classification'] == 'broad_acl_grant_observed' and not value['broad_grant_count']
                or value['classification'] == 'no_broad_grant_in_supported_acl' and value['broad_grant_count']):
            raise ValueError('Incomplete ACL projection')
        bucket_name(value['bucket'])
        if command['outcome'] == 'passed':
            report.update(value, outcome=('selected_acl_observed' if
                          value['status'] == value['second_status'] == 200 else 'acl_observation_incomplete'))
    except (OSError, ValueError, TypeError, KeyError):
        pass
    try:
        verified = lifetime_check(0) is True
    except Exception as error:
        verified = False
        report['lifetime_error_type'] = type(error).__name__
    if not verified:
        report.update(outcome='acl_observation_incomplete', classification='inconclusive', snapshot_stable=False)
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
