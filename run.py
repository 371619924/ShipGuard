import argparse
import json
import sys
from datetime import date
from pathlib import Path
from shipguard.engine import InputError,scan,sarif,safe_json


def main():
    p=argparse.ArgumentParser(description='Scoped local security gate; never applies infrastructure changes')
    p.add_argument('--repo',default='fixtures/safe');p.add_argument('--out',default='evidence/scan');p.add_argument('--as-of',default=date.today().isoformat());p.add_argument('--exceptions')
    args=p.parse_args();out=Path(args.out)
    try:
        as_of=date.fromisoformat(args.as_of)
        report=scan(args.repo,as_of,args.exceptions)
        out.mkdir(parents=True,exist_ok=True)
        (out/'Report.json').write_text(safe_json(report));(out/'Findings.sarif').write_text(safe_json(sarif(report)))
        print(json.dumps({k:report[k] for k in ('status','active_findings','suppressed_findings','scope')}));return int(report['active_findings']>0)
    except (InputError,OSError,ValueError,RecursionError,TypeError,KeyError) as error:
        # Do not print exception text: parsers and OS errors can echo source data.
        out.mkdir(parents=True,exist_ok=True)
        detail=str(error) if isinstance(error,InputError) else 'Input could not be completely analyzed; inspect supported scope and input types.'
        failure={'status':'error','error':detail}
        (out/'Report.json').write_text(safe_json(failure));(out/'Findings.sarif').unlink(missing_ok=True)
        print(json.dumps(failure),file=sys.stderr);return 2


if __name__=='__main__':sys.exit(main())
