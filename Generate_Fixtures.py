"""Deterministic, synthetic inputs and independently specified rule labels."""
import copy
import difflib
import json
import shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parent
FAKE_TOKEN='ghp_'+'A'*36


def baseline():
    sc={'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}
    pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':'demo','namespace':'sample'},'spec':{'automountServiceAccountToken':False,'securityContext':{'runAsNonRoot':True,'runAsUser':1001,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'app','image':'example.invalid/demo@sha256:'+'a'*64,'securityContext':sc}]}}
    def resource(typ,name,after):return {'mode':'managed','type':typ,'address':typ+'.'+name,'change':{'actions':['create'],'after':after,'after_unknown':{}}}
    group=resource('aws_security_group','app',{'ingress':[{'protocol':'tcp','from_port':443,'to_port':443,'cidr_blocks':['0.0.0.0/0'],'ipv6_cidr_blocks':[]}]})
    ebs=resource('aws_ebs_volume','data',{'encrypted':True})
    s3=resource('aws_s3_bucket_public_access_block','data',{k:True for k in ('block_public_acls','block_public_policy','ignore_public_acls','restrict_public_buckets')})
    iam=resource('aws_iam_policy','app',{'policy':json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':['s3:GetObject'],'Resource':['arn:aws:s3:::sample-only/*']}]})})
    return {'kubernetes':[pod],'terraform':{'format_version':'1.2','resource_changes':[group,ebs,s3,iam]},'python':'import subprocess\n\ndef process(value):\n    return subprocess.run(["printf", "%s", value], shell=False, check=True)\n','env':'# Synthetic configuration only\nMODE=demo\n'}


def container(d):return d['kubernetes'][0]['spec']['containers'][0]
def plan(d,index):return d['terraform']['resource_changes'][index]['change']


def change(d,rule):
    pod=d['kubernetes'][0]['spec'];sc=container(d)['securityContext']
    if rule=='KUB-NONROOT':pod['securityContext']['runAsNonRoot']=False
    elif rule=='KUB-PRIVILEGED':sc['privileged']=True
    elif rule=='KUB-ESCALATION':sc['allowPrivilegeEscalation']=True
    elif rule=='KUB-CAPABILITIES':sc['capabilities']={'drop':['ALL'],'add':['SYS_ADMIN']}
    elif rule=='KUB-SECCOMP':pod['securityContext']['seccompProfile']={'type':'Unconfined'}
    elif rule=='KUB-HOST':pod['hostPID']=True
    elif rule=='KUB-IMAGE':container(d)['image']='example.invalid/demo:latest'
    elif rule=='KUB-TOKEN':pod['automountServiceAccountToken']=True
    elif rule=='KUB-READONLY':sc['readOnlyRootFilesystem']=False
    elif rule=='TF-INGRESS':plan(d,0)['after']['ingress'][0].update(from_port=22,to_port=22)
    elif rule=='TF-ENCRYPTION':plan(d,1)['after']['encrypted']=False
    elif rule=='TF-PUBLICACCESS':plan(d,2)['after']['block_public_policy']=False
    elif rule=='TF-IAM':plan(d,3)['after']['policy']=json.dumps({'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]})
    elif rule=='TF-UNKNOWN':plan(d,1)['after_unknown']={'encrypted':True}
    elif rule=='PY-SHELL':d['python']='from subprocess import run as launch\nlaunch("echo demo", shell=True)\n'
    elif rule=='PY-DYNAMIC':d['python']='def process(value):\n    return eval(value)\n'
    elif rule=='SECRET-TOKEN':d['env']='# Deliberately synthetic detector fixture; never a real credential\nTOKEN='+FAKE_TOKEN+'\n'
    else:raise ValueError(rule)


def write_case(path,data):
    path=Path(path);(path/'src').mkdir(parents=True,exist_ok=True)
    (path/'manifest.json').write_text(json.dumps({'schema_version':1,'kubernetes_file':'kubernetes.json','terraform_file':'terraform.json','source_files':['src/service.py','config.env']},indent=2)+'\n')
    (path/'kubernetes.json').write_text(json.dumps(data['kubernetes'],indent=2)+'\n')
    (path/'terraform.json').write_text(json.dumps(data['terraform'],indent=2)+'\n')
    (path/'src/service.py').write_text(data['python']);(path/'config.env').write_text(data['env'])


def main():
    rules=['KUB-NONROOT','KUB-PRIVILEGED','KUB-ESCALATION','KUB-CAPABILITIES','KUB-SECCOMP','KUB-HOST','KUB-IMAGE','KUB-TOKEN','KUB-READONLY','TF-INGRESS','TF-ENCRYPTION','TF-PUBLICACCESS','TF-IAM','TF-UNKNOWN','PY-SHELL','PY-DYNAMIC','SECRET-TOKEN']
    labels=[];fixtures=ROOT/'fixtures'
    write_case(fixtures/'safe',baseline());write_case(ROOT/'repository',baseline())
    for rule in rules:
        d=baseline();change(d,rule);name=rule.lower().replace('-','_');write_case(fixtures/name,d);labels.append({'case':name,'expected_rules':[rule]})
    clean={};clean['clean_baseline']=baseline()
    d=baseline();d['kubernetes'][0]['spec']['securityContext']['runAsUser']=0;container(d)['securityContext']['runAsUser']=1001;clean['container_override']=d
    d=baseline();plan(d,0)['after']['ingress'][0].update(from_port=22,to_port=22,cidr_blocks=['10.0.0.0/8']);clean['scoped_admin']=d
    d=baseline();plan(d,1)['after_unknown']={'id':True};clean['unknown_identifier']=d
    d=baseline();plan(d,1).update(actions=['delete'],after=None);clean['deleted_resource']=d
    d=baseline();d['python']='import subprocess as sp\nsp.run(["echo", "demo"], shell=False)\n';clean['safe_subprocess']=d
    d=baseline();plan(d,3)['after']['policy']=json.dumps({'Statement':[{'Effect':'Deny','Action':'*','Resource':'*'}]});clean['deny_wildcard']=d
    for name,d in clean.items():write_case(fixtures/name,d);labels.append({'case':name,'expected_rules':[]})
    (fixtures/'Labels.json').write_text(json.dumps({'notice':'Synthetic hand-labeled cases; expected sets are specified before running the scanner.','cases':labels},indent=2)+'\n')
    unsafe=baseline()
    for rule in rules:
        if rule not in ('TF-UNKNOWN','PY-DYNAMIC'):change(unsafe,rule)
    unsafe['python']+='eval("1+1")\n'
    extra=copy.deepcopy(unsafe['terraform']['resource_changes'][1]);extra['address']='aws_ebs_volume.pending';extra['change']['after_unknown']={'encrypted':True};unsafe['terraform']['resource_changes'].append(extra)
    write_case(fixtures/'unsafe',unsafe)
    diffs=[]
    for name in ['kubernetes.json','terraform.json','src/service.py','config.env']:
        a=(fixtures/'unsafe'/name).read_text().splitlines(True);b=(fixtures/'safe'/name).read_text().splitlines(True)
        diffs.extend(difflib.unified_diff(a,b,fromfile='unsafe/'+name,tofile='safe/'+name))
    (fixtures/'Reviewed_Changes.patch').write_text(''.join(diffs))
    print(json.dumps({'labeled_cases':len(labels),'positive_cases':len(rules),'clean_cases':len(clean),'credential_fixture':'synthetic only'}))


if __name__=='__main__':main()
