"""Guarded read-only whole bucket-policy capture; no implicit privacy verdict."""
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
    semantics = (directory / 'storage_policy_semantics.py').read_text()
    # Modules execute in separate namespaces; the canary's main is never invoked.
    prefix = ('import hashlib,json,sys\n'
              'support={"__name__":"trusted_policy_signing"}\n'
              'exec(compile(' + repr(support) + ',"trusted-signing","exec"),support)\n'
              'semantics={"__name__":"trusted_policy_semantics"}\n'
              'exec(compile(' + repr(semantics) + ',"trusted-semantics","exec"),semantics)\n')
    return prefix + '''
report=dict(classification='inconclusive',snapshot_stable=False)
try:
 config=support['private_binding'](sys.argv[1]);peer=support['Peer'](config)
 def read_policy():
  peer.check(5)
  path='/'+config['bucket'];query='policy='
  timestamp=support['datetime'].now(support['timezone'].utc).strftime('%Y%m%dT%H%M%SZ')
  headers=support['signed_headers'](config,'GET',path,query,b'',timestamp)
  request=support['urllib'].request.Request(config['endpoint']+path+'?'+query,headers=headers,method='GET')
  try:response=peer.opener.open(request,timeout=5)
  except support['urllib'].error.HTTPError as error:response=error
  with response:status=response.status;raw=response.read(65537)
  peer.check()
  result=semantics['classify_response'](status,raw,config['bucket'])
  identity=hashlib.sha256(b'NoSuchBucketPolicy' if status==404 else raw).hexdigest()
  return result,identity
 first,before=read_policy();second,after=read_policy()
 report.update(first,bucket=config['bucket'],policy_sha256=before,second_policy_sha256=after,
               snapshot_stable=before==after and first==second)
 if not report['snapshot_stable']:report['classification']='inconclusive'
except BaseException as error:report['error_type']=type(error).__name__
print(json.dumps(report,allow_nan=False))
'''


def capture_bucket_policy(attempt, *, peer_prefix, private_binding_path,
                          lifetime_check, label='foundation-storage-policy'):
    if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
            or any(not isinstance(v, str) or not v or len(v)>1024 or '\x00' in v for v in peer_prefix)
            or not isinstance(private_binding_path,str) or not private_binding_path.startswith('/')
            or len(private_binding_path)>4096 or '\x00' in private_binding_path
            or not callable(lifetime_check) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}',label)):
        raise ValueError('Bounded independently verified policy peer required')
    if lifetime_check(35) is not True:raise Inconclusive('Policy peer lifetime unavailable')
    source=probe_source()
    command=collect(attempt,label,[*peer_prefix,'python3','-c',source,private_binding_path],
                    cwd=Path(__file__).resolve().parents[1],timeout=30,max_output_bytes=8192)
    report=dict(outcome='policy_observation_incomplete',classification='inconclusive',
                snapshot_stable=False,privacy_verified=None,command=command,
                probe_sha256=hashlib.sha256(source.encode()).hexdigest(),
                limits='Declared whole-bucket policy only; ACLs, other authorization controls, '
                       'concurrent unseen changes and application object access remain unverified. '
                       'No whole-bucket privacy or AC-001 acceptance verdict.')
    try:
        value=json.loads((attempt.directory/label/'stdout.log').read_text(),object_pairs_hook=unique_pairs)
        fields={'classification','snapshot_stable','bucket','policy_sha256','second_policy_sha256',
                'statement_count','public_grant_count','unsupported_statement_count','explicit_deny_present'}
        if (not isinstance(value,dict) or set(value)!=fields
                or value['classification'] not in ('inconclusive','bucket_policy_absent',
                    'unconditional_broad_grant_observed','no_broad_grant_in_supported_policy')
                or any(type(value[k]) is not bool for k in ('snapshot_stable','explicit_deny_present'))
                or any(type(value[k]) is not int or not 0<=value[k]<=64 for k in (
                    'statement_count','public_grant_count','unsupported_statement_count'))
                or any(not isinstance(value[k],str) or not re.fullmatch(r'[0-9a-f]{64}',value[k])
                       for k in ('policy_sha256','second_policy_sha256'))
                or value['snapshot_stable'] and value['policy_sha256']!=value['second_policy_sha256']
                or not value['snapshot_stable'] and value['classification']!='inconclusive'):
            raise ValueError('Incomplete policy projection')
        bucket_name(value['bucket'])
        if command['outcome']=='passed':report.update(value,outcome='bucket_policy_observed')
    except (OSError,ValueError,TypeError,KeyError):pass
    try:verified=lifetime_check(0) is True
    except Exception as error:
        verified=False;report['lifetime_error_type']=type(error).__name__
    if not verified:
        report.update(outcome='policy_observation_incomplete',classification='inconclusive',snapshot_stable=False)
    atomic_json(attempt.directory/(label+'.json'),report)
    return report
