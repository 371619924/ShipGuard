import json
from datetime import date
from pathlib import Path
from shipguard.engine import scan
ROOT=Path(__file__).resolve().parent


def main():
    labels=json.loads((ROOT/'fixtures/Labels.json').read_text())['cases'];results=[];tp=fp=fn=0
    for c in labels:
        r=scan(ROOT/'fixtures'/c['case'],date(2026,10,30));actual=set(x['rule'] for x in r['findings']);expected=set(c['expected_rules'])
        tp+=len(actual&expected);fp+=len(actual-expected);fn+=len(expected-actual)
        results.append({'case':c['case'],'expected_rules':sorted(expected),'actual_rules':sorted(actual),'passed':actual==expected})
    data={'scope':'24 synthetic cases with manually specified rule sets, not a production vulnerability benchmark','cases':results,'true_positive_rule_hits':tp,'false_positive_rule_hits':fp,'false_negative_rule_hits':fn,'passed':all(x['passed'] for x in results)}
    out=ROOT/'evidence';out.mkdir(exist_ok=True);(out/'Evaluation_Results.json').write_text(json.dumps(data,indent=2))
    assert data['passed'],results
    print(json.dumps({k:v for k,v in data.items() if k!='cases'}))


if __name__=='__main__':main()
