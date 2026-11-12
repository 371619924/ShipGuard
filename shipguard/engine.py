import ast
import hashlib
import ipaddress
import json
import re
from datetime import date
from pathlib import Path,PurePosixPath


class InputError(ValueError):
    pass


RULES={
 'KUB-NONROOT':'Require effective non-root execution and prohibit explicit UID zero.',
 'KUB-PRIVILEGED':'Do not enable privileged containers.',
 'KUB-ESCALATION':'Explicitly disable privilege escalation.',
 'KUB-CAPABILITIES':'Drop ALL capabilities and add back only NET_BIND_SERVICE if needed.',
 'KUB-SECCOMP':'Use RuntimeDefault or an explicitly configured Localhost seccomp profile.',
 'KUB-HOST':'Do not share host namespaces or mount hostPath volumes.',
 'KUB-IMAGE':'Reference container images with a full sha256 digest.',
 'KUB-TOKEN':'Disable automatic service-account token mounting for this baseline.',
 'KUB-READONLY':'Use a read-only root filesystem for this baseline.',
 'TF-INGRESS':'Restrict public SSH and RDP ingress, including all-protocol access.',
 'TF-ENCRYPTION':'Explicitly enable EBS volume encryption.',
 'TF-PUBLICACCESS':'Enable all four S3 public access block settings.',
 'TF-IAM':'Do not combine global action and global resource wildcards in an Allow statement.',
 'TF-UNKNOWN':'Resolve unknown security-relevant planned values before approving.',
 'PY-SHELL':'Avoid literal shell=True in supported subprocess calls.',
 'PY-DYNAMIC':'Avoid direct eval or exec calls on this static baseline.',
 'SECRET-TOKEN':'Remove supported credential-shaped literals and rotate actual exposed credentials.'
}
TOKEN=re.compile(r'(?<![A-Za-z0-9])(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{36})(?![A-Za-z0-9])')
DIGEST=re.compile(r'[^\s@]+@sha256:[0-9a-fA-F]{64}')
MAX_FILE=262144


def obj(value):
    if not isinstance(value,dict):raise InputError('Expected a JSON object')
    return value


def array(value):
    if not isinstance(value,list):raise InputError('Expected a JSON array')
    return value


def boolean(value):
    if type(value) is not bool:raise InputError('Expected a boolean security setting')
    return value


def integer(value):
    if type(value) is not int:raise InputError('Expected an integer setting')
    return value


def text(value):
    if not isinstance(value,str) or not value:raise InputError('Expected nonempty text')
    return value


def strings(value):
    items=array(value)
    if not all(isinstance(x,str) for x in items):raise InputError('Expected string entries')
    return items


def parse_json(raw):
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise InputError('Duplicate JSON key')
            out[k]=v
        return out
    def constant(_):raise InputError('Nonfinite JSON number')
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
    except (json.JSONDecodeError,RecursionError) as e:raise InputError('Invalid JSON input') from e


def scoped_file(root,name):
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_./-]+',name):raise InputError('Invalid manifest path')
    p=PurePosixPath(name)
    if p.is_absolute() or any(x in ('','..','.') for x in name.split('/')):raise InputError('Unsafe manifest path')
    candidate=root.joinpath(*p.parts)
    cursor=root
    for part in p.parts:
        cursor=cursor/part
        if cursor.is_symlink():raise InputError('Symlink inputs are not supported')
    if not candidate.is_file() or not candidate.resolve().is_relative_to(root.resolve()):raise InputError('Input is missing or outside repository')
    if candidate.stat().st_size>MAX_FILE:raise InputError('Input exceeds the local size limit')
    try:return candidate.read_text(encoding='utf-8')
    except UnicodeError as e:raise InputError('Input is not UTF-8') from e


def finding(rule,uri,pointer='',line=1):
    fp=hashlib.sha256(f'{rule}|{uri}|{pointer}|{line}'.encode()).hexdigest()
    return {'rule':rule,'uri':uri,'pointer':pointer,'line':line,'message':RULES[rule],'fingerprint':fp,'suppressed':False}


def security_context(value):
    sc=obj(value)
    for k in ('runAsNonRoot','privileged','allowPrivilegeEscalation','readOnlyRootFilesystem'):
        if k in sc:boolean(sc[k])
    if 'runAsUser' in sc:
        if integer(sc['runAsUser'])<0:raise InputError('UID must be nonnegative')
    if 'capabilities' in sc:
        caps=obj(sc['capabilities'])
        for k in ('drop','add'):
            if k in caps:strings(caps[k])
    if 'seccompProfile' in sc:
        profile=obj(sc['seccompProfile']);text(profile.get('type'))
        if profile['type']=='Localhost':text(profile.get('localhostProfile'))
    return sc


def check_kubernetes(document,uri):
    resources=array(document)
    if not resources:raise InputError('Kubernetes scope must not be empty')
    out=[];count=0;identities=set()
    for i,item in enumerate(resources):
        r=obj(item);kind=r.get('kind');meta=obj(r.get('metadata'));name=text(meta.get('name'))
        ident=(kind,meta.get('namespace','default'),name)
        if ident in identities:raise InputError('Duplicate Kubernetes object identity')
        identities.add(ident)
        base=f'/{i}/spec'
        if kind=='Pod' and r.get('apiVersion')=='v1':pod=obj(r.get('spec'))
        elif kind=='Deployment' and r.get('apiVersion')=='apps/v1':
            pod=obj(obj(obj(r.get('spec')).get('template')).get('spec'));base+='/template/spec'
        else:raise InputError('Unsupported Kubernetes kind or API version')
        if obj(pod.get('os',{})).get('name','linux')!='linux':raise InputError('This baseline supports Linux pods only')
        psc=security_context(pod.get('securityContext',{}))
        for field in ('hostNetwork','hostPID','hostIPC','automountServiceAccountToken'):
            if field in pod:boolean(pod[field])
        if any(pod.get(f,False) for f in ('hostNetwork','hostPID','hostIPC')) or any('hostPath' in obj(v) for v in array(pod.get('volumes',[]))):out.append(finding('KUB-HOST',uri,base))
        if pod.get('automountServiceAccountToken') is not False:out.append(finding('KUB-TOKEN',uri,base+'/automountServiceAccountToken'))
        if not array(pod.get('containers')):raise InputError('Pod must declare a container')
        container_names=set()
        for group in ('containers','initContainers','ephemeralContainers'):
            for j,c in enumerate(array(pod.get(group,[]))):
                c=obj(c);cn=text(c.get('name'))
                if cn in container_names:raise InputError('Duplicate container name')
                container_names.add(cn);count+=1;sc=security_context(c.get('securityContext',{}));where=f'{base}/{group}/{j}'
                effective_nonroot=sc.get('runAsNonRoot',psc.get('runAsNonRoot'))
                uid=sc.get('runAsUser',psc.get('runAsUser'))
                if effective_nonroot is not True or uid==0:out.append(finding('KUB-NONROOT',uri,where+'/securityContext'))
                if sc.get('privileged',False):out.append(finding('KUB-PRIVILEGED',uri,where+'/securityContext/privileged'))
                if sc.get('allowPrivilegeEscalation') is not False:out.append(finding('KUB-ESCALATION',uri,where+'/securityContext/allowPrivilegeEscalation'))
                caps=sc.get('capabilities',{})
                if 'ALL' not in caps.get('drop',[]) or set(caps.get('add',[]))-{'NET_BIND_SERVICE'}:out.append(finding('KUB-CAPABILITIES',uri,where+'/securityContext/capabilities'))
                seccomp=sc.get('seccompProfile',psc.get('seccompProfile',{}))
                if seccomp.get('type') not in ('RuntimeDefault','Localhost'):out.append(finding('KUB-SECCOMP',uri,where+'/securityContext/seccompProfile'))
                if sc.get('readOnlyRootFilesystem') is not True:out.append(finding('KUB-READONLY',uri,where+'/securityContext/readOnlyRootFilesystem'))
                if not DIGEST.fullmatch(text(c.get('image'))):out.append(finding('KUB-IMAGE',uri,where+'/image'))
    return out,count


CRITICAL={
 'aws_security_group':['ingress'],
 'aws_vpc_security_group_ingress_rule':['ip_protocol','from_port','to_port','cidr_ipv4','cidr_ipv6'],
 'aws_ebs_volume':['encrypted'],
 'aws_s3_bucket_public_access_block':['block_public_acls','block_public_policy','ignore_public_acls','restrict_public_buckets'],
 'aws_iam_policy':['policy']
}


def unknown_tree(value):
    if value is True:return True
    if isinstance(value,dict):return any(unknown_tree(v) for v in value.values())
    if isinstance(value,list):return any(unknown_tree(v) for v in value)
    if value is not False:raise InputError('Invalid after_unknown tree')
    return False


def public_network(value):
    try:return ipaddress.ip_network(text(value),strict=False).prefixlen==0
    except ValueError as e:raise InputError('Invalid ingress CIDR') from e


def dangerous_ingress(rule,modern=False):
    protocol=rule.get('ip_protocol' if modern else 'protocol')
    if protocol not in ('tcp','6','-1','udp','17','icmp','1','58','icmpv6'):raise InputError('Unsupported ingress protocol')
    if modern:
        nets=[rule[k] for k in ('cidr_ipv4','cidr_ipv6') if rule.get(k) is not None]
    else:nets=strings(rule.get('cidr_blocks',[]))+strings(rule.get('ipv6_cidr_blocks',[]))
    world=any(public_network(x) for x in nets)
    if protocol=='-1':return world
    low=integer(rule.get('from_port'));high=integer(rule.get('to_port'))
    if protocol in ('tcp','6') and (low<0 or high>65535 or low>high):raise InputError('Invalid TCP port range')
    return world and protocol in ('tcp','6') and any(low<=port<=high for port in (22,3389))


def check_terraform(document,uri):
    doc=obj(document);version=text(doc.get('format_version'))
    if not re.fullmatch(r'1\.\d+',version):raise InputError('Unsupported Terraform plan format major version')
    changes=array(doc.get('resource_changes'))
    if not changes:raise InputError('Terraform scope must not be empty')
    out=[];count=0;seen=set()
    for i,item in enumerate(changes):
        r=obj(item);address=text(r.get('address'))
        if address in seen:raise InputError('Duplicate Terraform resource address')
        seen.add(address);typ=r.get('type')
        if r.get('mode')!='managed' or typ not in CRITICAL:raise InputError('Unsupported Terraform resource scope')
        change=obj(r.get('change'));actions=strings(change.get('actions'))
        if actions==['delete']:continue
        if actions not in (['create'],['update'],['no-op'],['delete','create'],['create','delete']):raise InputError('Unsupported Terraform change action')
        count+=1;after=obj(change.get('after'));unknown=obj(change.get('after_unknown',{}));where=f'/resource_changes/{i}/change/after'
        for v in unknown.values():unknown_tree(v)
        if any(unknown_tree(unknown[k]) for k in CRITICAL[typ] if k in unknown):
            out.append(finding('TF-UNKNOWN',uri,where));continue
        if typ=='aws_security_group':
            if any(dangerous_ingress(obj(r)) for r in array(after.get('ingress'))):out.append(finding('TF-INGRESS',uri,where+'/ingress'))
        elif typ=='aws_vpc_security_group_ingress_rule':
            if dangerous_ingress(after,True):out.append(finding('TF-INGRESS',uri,where))
        elif typ=='aws_ebs_volume':
            if 'encrypted' in after and after['encrypted'] is not None:boolean(after['encrypted'])
            if after.get('encrypted') is not True:out.append(finding('TF-ENCRYPTION',uri,where+'/encrypted'))
        elif typ=='aws_s3_bucket_public_access_block':
            for key in CRITICAL[typ]:
                if key in after and after[key] is not None:boolean(after[key])
            if any(after.get(k) is not True for k in CRITICAL[typ]):out.append(finding('TF-PUBLICACCESS',uri,where))
        elif typ=='aws_iam_policy':
            policy=obj(parse_json(text(after.get('policy'))));statements=policy.get('Statement')
            statements=[statements] if isinstance(statements,dict) else array(statements)
            for statement in statements:
                s=obj(statement)
                if s.get('Effect') not in ('Allow','Deny'):raise InputError('Invalid IAM effect')
                if 'NotAction' in s or 'NotResource' in s:raise InputError('IAM complements require unsupported semantic analysis')
                acts=[s['Action']] if isinstance(s.get('Action'),str) else strings(s.get('Action'))
                resources=[s['Resource']] if isinstance(s.get('Resource'),str) else strings(s.get('Resource'))
                if s['Effect']=='Allow' and '*' in acts and '*' in resources:
                    out.append(finding('TF-IAM',uri,where+'/policy'));break
    return out,count


def check_python(raw,uri):
    try:tree=ast.parse(raw)
    except SyntaxError as e:raise InputError('Python source has a syntax error') from e
    aliases={}
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):
            for alias in node.names:aliases[alias.asname or alias.name]=alias.name
        elif isinstance(node,ast.ImportFrom) and node.module=='subprocess':
            for alias in node.names:aliases[alias.asname or alias.name]='subprocess.'+alias.name
    out=[]
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call):continue
        target=''
        if isinstance(node.func,ast.Name):target=aliases.get(node.func.id,node.func.id)
        elif isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):target=aliases.get(node.func.value.id,node.func.value.id)+'.'+node.func.attr
        if target in ('subprocess.run','subprocess.Popen','subprocess.call','subprocess.check_call','subprocess.check_output') and any(k.arg=='shell' and isinstance(k.value,ast.Constant) and bool(k.value.value) for k in node.keywords):out.append(finding('PY-SHELL',uri,line=node.lineno))
        if target in ('eval','exec'):out.append(finding('PY-DYNAMIC',uri,line=node.lineno))
    return out


def apply_exceptions(findings,entries,as_of):
    seen=set();by_fp={f['fingerprint']:f for f in findings}
    for item in array(entries):
        ex=obj(item);fp=text(ex.get('fingerprint'));text(ex.get('owner'));text(ex.get('reason'))
        try:expires=date.fromisoformat(text(ex.get('expires')))
        except ValueError as e:raise InputError('Invalid exception expiry') from e
        if fp in seen:raise InputError('Duplicate exception')
        seen.add(fp)
        if fp not in by_fp:raise InputError('Exception does not match a current finding')
        if expires<as_of:raise InputError('Exception has expired')
        f=by_fp[fp]
        if f['rule']=='TF-UNKNOWN':raise InputError('Unknown planned security values cannot be waived')
        f.update(suppressed=True,exception={'owner':ex['owner'],'reason':ex['reason'],'expires':expires.isoformat()})
    return findings


def scan(root,as_of,exceptions=None):
    root=Path(root).resolve();manifest=obj(parse_json(scoped_file(root,'manifest.json')))
    if type(manifest.get('schema_version')) is not int or manifest.get('schema_version')!=1:raise InputError('Unsupported manifest version')
    kname=text(manifest.get('kubernetes_file'));tname=text(manifest.get('terraform_file'));sources=strings(manifest.get('source_files'))
    names=[kname,tname]+sources
    if len(set(names))!=len(names):raise InputError('Duplicate input path')
    if len(names)>32:raise InputError('Too many inputs for this local baseline')
    inputs={name:scoped_file(root,name) for name in names}
    if sum(len(v.encode()) for v in inputs.values())>1048576:raise InputError('Total scope exceeds the local size limit')
    findings,kcount=check_kubernetes(parse_json(inputs[kname]),kname)
    tf,tcount=check_terraform(parse_json(inputs[tname]),tname);findings+=tf
    pycount=0
    for name,raw in inputs.items():
        if name in sources and name.endswith('.py'):findings+=check_python(raw,name);pycount+=1
        for line_num,line in enumerate(raw.splitlines(),1):
            if TOKEN.search(line):findings.append(finding('SECRET-TOKEN',name,line=line_num))
    findings.sort(key=lambda f:(f['uri'],f['pointer'],f['line'],f['rule']))
    if exceptions is not None:apply_exceptions(findings,parse_json(scoped_file(root,exceptions)),as_of)
    active=sum(not f['suppressed'] for f in findings)
    return {'tool':'ShipGuard','as_of':as_of.isoformat(),'status':'blocked' if active else 'clean','active_findings':active,'suppressed_findings':len(findings)-active,'scope':{'input_files':len(names),'kubernetes_containers':kcount,'terraform_resources':tcount,'python_files':pycount},'findings':findings}


def sarif(report):
    results=[]
    for f in report['findings']:
        r={'ruleId':f['rule'],'level':'error','message':{'text':f['message']},'locations':[{'physicalLocation':{'artifactLocation':{'uri':f['uri']},'region':{'startLine':f['line']}}}],'partialFingerprints':{'shipguard/v1':f['fingerprint']},'properties':{'jsonPointer':f['pointer']}}
        if f['suppressed']:r['suppressions']=[{'kind':'external','status':'accepted','justification':f['exception']['reason']}]
        results.append(r)
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'ShipGuard','version':'1.0','rules':[{'id':k,'shortDescription':{'text':v}} for k,v in RULES.items()]}},'results':results}]}


def safe_json(value):
    return TOKEN.sub('[REDACTED]',json.dumps(value,indent=2,sort_keys=True))+'\n'
