"""Run source-only validation, retaining command logs and structured status."""
import json,subprocess,sys,tempfile,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parent
COMMANDS=[['-m','unittest','discover','-s','tests','-v'],['integration.py'],['evaluate.py'],['check_workflow.py'],['run.py','--repo','repository','--out','evidence/repository','--as-of','2026-10-30'],['-m','edge_update.run_validation']]
def validate(root):
 out=root/'evidence';out.mkdir(exist_ok=True);records=[]
 for i,args in enumerate(COMMANDS):
  r=subprocess.run([sys.executable,*args],cwd=root,capture_output=True,text=True,timeout=45)
  (out/f'Stage_{i+1}_Log.txt').write_text(r.stdout+r.stderr)
  records.append({'arguments':args,'exit_code':r.returncode})
  if r.returncode:raise RuntimeError(records[-1])
 return records
def main():
 records=validate(ROOT)
 with tempfile.TemporaryDirectory() as td:
  fresh=Path(td)/'ShipGuard';shutil.copytree(ROOT,fresh,ignore=shutil.ignore_patterns('evidence','__pycache__','*.pyc','.git'))
  clean=validate(fresh)
  before=json.loads((ROOT/'evidence/edge_update/Results.json').read_text());after=json.loads((fresh/'evidence/edge_update/Results.json').read_text())
  assert before==after
  result={'stages':records,'fresh_source_stages':clean,'source_only_reproduction':True,'edge_results_match':True}
  (ROOT/'evidence/Reproduction_Results.json').write_text(json.dumps(result,indent=2))
 print(json.dumps({'stages':len(records),'fresh_source_stages':len(clean),'edge_cases':before['tests'],'passed':True}))
if __name__=='__main__':main()
