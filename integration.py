import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from Generate_Fixtures import FAKE_TOKEN

ROOT=Path(__file__).resolve().parent


def main():
    checks=[];transcripts=[]
    def check(name,condition):
        checks.append({'name':name,'passed':bool(condition)})
        if not condition:raise AssertionError(name)
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);out=td/'out'
        def run(repo,extra=None):
            command=[sys.executable,'run.py','--repo',str(repo),'--out',str(out),'--as-of','2026-10-30']+(extra or [])
            p=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,timeout=10)
            transcripts.append({'arguments':command[2:],'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
            return p,json.loads((out/'Report.json').read_text())
        p,r=run(ROOT/'fixtures/safe');check('Clean inputs return zero with declared coverage',p.returncode==0 and r['scope']=={'input_files':4,'kubernetes_containers':1,'terraform_resources':4,'python_files':1})
        p,r=run(ROOT/'fixtures/unsafe');check('Unsafe inputs return one with seventeen rule findings',p.returncode==1 and r['active_findings']==17)
        sf=json.loads((out/'Findings.sarif').read_text());check('SARIF contains rule IDs locations and deterministic fingerprints',sf['version']=='2.1.0' and len(sf['runs'][0]['results'])==17 and all('partialFingerprints' in x and 'locations' in x for x in sf['runs'][0]['results']))
        check('Credential fixture is absent from output and process logs',all(FAKE_TOKEN not in s for s in [(out/'Report.json').read_text(),(out/'Findings.sarif').read_text(),p.stdout,p.stderr]))
        previous=(out/'Report.json').read_bytes();p,r=run(ROOT/'fixtures/unsafe');check('Repeated CLI output is deterministic',p.returncode==1 and previous==(out/'Report.json').read_bytes())
        repo=td/'repo';shutil.copytree(ROOT/'fixtures/unsafe',repo)
        for rel in ['kubernetes.json','terraform.json','src/service.py','config.env']:shutil.copy2(ROOT/'fixtures/safe'/rel,repo/rel)
        p,r=run(repo);check('Reviewed replacement configurations remove the fixture findings',p.returncode==0 and r['active_findings']==0)
        (repo/'kubernetes.json').write_text('{bad');p,r=run(repo);check('Invalid JSON returns two and removes stale SARIF',p.returncode==2 and r['status']=='error' and not (out/'Findings.sarif').exists())
        shutil.copy2(ROOT/'fixtures/safe/kubernetes.json',repo/'kubernetes.json');(repo/'config.env').unlink();p,r=run(repo);check('Missing declared input fails closed',p.returncode==2)
        shutil.rmtree(repo);shutil.copytree(ROOT/'fixtures/kub_image',repo);p,r=run(repo);fp=r['findings'][0]['fingerprint']
        ex={'fingerprint':fp,'owner':'sample-team','reason':'temporary compatibility review','expires':'2026-10-31'};(repo/'exceptions.json').write_text(json.dumps([ex]))
        p,r=run(repo,['--exceptions','exceptions.json']);check('Current exact waiver returns zero while retaining suppressed finding',p.returncode==0 and r['active_findings']==0 and r['suppressed_findings']==1 and len(r['findings'])==1)
        ex['expires']='2026-10-29';(repo/'exceptions.json').write_text(json.dumps([ex]));p,r=run(repo,['--exceptions','exceptions.json']);check('Expired waiver returns two',p.returncode==2)
        ex.update(expires='2026-11-01',fingerprint='0'*64);(repo/'exceptions.json').write_text(json.dumps([ex]));p,r=run(repo,['--exceptions','exceptions.json']);check('Stale wildcard-like waiver cannot bypass findings',p.returncode==2)
        m=json.loads((repo/'manifest.json').read_text());m['source_files']=['../outside.py'];(repo/'manifest.json').write_text(json.dumps(m));p,r=run(repo);check('Escaping input path fails closed',p.returncode==2)
        shutil.rmtree(repo);shutil.copytree(ROOT/'fixtures/safe',repo);(repo/'src/service.py').write_text('def bad(:\n');p,r=run(repo);check('Unparseable Python returns two',p.returncode==2)
        shutil.copy2(ROOT/'fixtures/safe/src/service.py',repo/'src/service.py');tf=json.loads((repo/'terraform.json').read_text());tf['resource_changes'][0]['type']='aws_instance';(repo/'terraform.json').write_text(json.dumps(tf));p,r=run(repo);check('Unsupported resource type does not produce a clean pass',p.returncode==2)
        p,r=run(ROOT/'fixtures/tf_unknown');check('Unknown security relevant plan value blocks the gate',p.returncode==1 and {x['rule'] for x in r['findings']}=={'TF-UNKNOWN'})
        p,r=run(ROOT/'fixtures/unknown_identifier');check('Unknown computed identifier alone does not block',p.returncode==0)
    evidence=ROOT/'evidence';evidence.mkdir(exist_ok=True)
    (evidence/'Integration_Results.json').write_text(json.dumps({'scope':'Local subprocess CLI and files; GitHub hosted workflow not executed','checks':checks},indent=2))
    (evidence/'CLI_Transcripts.json').write_text(json.dumps(transcripts,indent=2));assert len(checks)==16
    print(json.dumps({'checks':len(checks),'passed':sum(x['passed'] for x in checks)}))


if __name__=='__main__':main()
