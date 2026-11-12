import copy
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from Generate_Fixtures import baseline,container,plan,change,write_case,FAKE_TOKEN
from shipguard.engine import InputError,MAX_FILE,parse_json,scan,sarif,safe_json,apply_exceptions

AS_OF=date(2026,10,30)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.data=baseline();write_case(self.root,self.data)
    def run_data(self):
        write_case(self.root,self.data);return scan(self.root,AS_OF)
    def rules(self):return {x['rule'] for x in self.run_data()['findings']}
    def test_clean_fixture(self):self.assertEqual(self.run_data()['status'],'clean')
    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(InputError):parse_json('{"a":1,"a":2}')
    def test_nonfinite_json_rejected(self):
        with self.assertRaises(InputError):parse_json('{"a":NaN}')
    def test_traversal_path_rejected(self):
        p=self.root/'manifest.json';m=json.loads(p.read_text());m['source_files']=['../outside.py'];p.write_text(json.dumps(m))
        with self.assertRaises(InputError):scan(self.root,AS_OF)
    def test_symlink_input_rejected(self):
        src=self.root/'src/service.py';src.unlink();src.symlink_to(self.root/'config.env')
        with self.assertRaises(InputError):scan(self.root,AS_OF)
    def test_file_size_limit(self):
        (self.root/'config.env').write_text('a'*(MAX_FILE+1))
        with self.assertRaises(InputError):scan(self.root,AS_OF)
    def test_string_boolean_cannot_bypass_security(self):
        container(self.data)['securityContext']['allowPrivilegeEscalation']='false'
        with self.assertRaises(InputError):self.run_data()
    def test_deployment_template_is_scanned(self):
        pod=self.data['kubernetes'][0];spec=pod['spec'];container(self.data)['securityContext']['privileged']=True
        self.data['kubernetes']=[{'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'demo'},'spec':{'template':{'spec':spec}}}]
        r=self.run_data();self.assertIn('KUB-PRIVILEGED',{x['rule'] for x in r['findings']});self.assertIn('/template/spec/',r['findings'][0]['pointer'])
    def test_init_container_is_scanned(self):
        init=copy.deepcopy(container(self.data));init['name']='init';init['securityContext']['privileged']=True;self.data['kubernetes'][0]['spec']['initContainers']=[init]
        self.assertIn('KUB-PRIVILEGED',self.rules())
    def test_ephemeral_container_is_scanned(self):
        ep=copy.deepcopy(container(self.data));ep['name']='debug';ep['securityContext']['allowPrivilegeEscalation']=True;self.data['kubernetes'][0]['spec']['ephemeralContainers']=[ep]
        self.assertIn('KUB-ESCALATION',self.rules())
    def test_container_uid_overrides_pod_uid(self):
        self.data['kubernetes'][0]['spec']['securityContext']['runAsUser']=0;container(self.data)['securityContext']['runAsUser']=1001
        self.assertNotIn('KUB-NONROOT',self.rules())
    def test_host_path_blocks_even_without_host_network(self):
        self.data['kubernetes'][0]['spec']['volumes']=[{'name':'host','hostPath':{'path':'/tmp'}}]
        self.assertIn('KUB-HOST',self.rules())
    def test_unsupported_kind_fails(self):
        self.data['kubernetes'][0]['kind']='Job'
        with self.assertRaises(InputError):self.run_data()
    def test_empty_containers_not_clean(self):
        self.data['kubernetes'][0]['spec']['containers']=[]
        with self.assertRaises(InputError):self.run_data()
    def test_unknown_security_value_blocks(self):
        plan(self.data,1)['after_unknown']={'encrypted':True}
        self.assertIn('TF-UNKNOWN',self.rules())
    def test_unknown_nonsecurity_identifier_is_ignored(self):
        plan(self.data,1)['after_unknown']={'id':True}
        self.assertEqual(self.rules(),set())
    def test_ipv6_public_rdp_is_detected(self):
        plan(self.data,0)['after']['ingress'][0].update(from_port=3389,to_port=3389,cidr_blocks=[],ipv6_cidr_blocks=['::/0'])
        self.assertIn('TF-INGRESS',self.rules())
    def test_all_protocol_public_ingress_is_detected(self):
        plan(self.data,0)['after']['ingress'][0].update(protocol='-1')
        self.assertIn('TF-INGRESS',self.rules())
    def test_replacement_checks_after_values(self):
        plan(self.data,1).update(actions=['delete','create']);plan(self.data,1)['after']['encrypted']=False
        self.assertIn('TF-ENCRYPTION',self.rules())
    def test_delete_only_resource_is_not_a_deploy_target(self):
        plan(self.data,1).update(actions=['delete'],after=None)
        r=self.run_data();self.assertEqual(r['active_findings'],0);self.assertEqual(r['scope']['terraform_resources'],3)
    def test_unsupported_resource_is_not_silently_skipped(self):
        self.data['terraform']['resource_changes'][0]['type']='aws_instance'
        with self.assertRaises(InputError):self.run_data()
    def test_duplicate_resource_address_rejected(self):
        self.data['terraform']['resource_changes'].append(copy.deepcopy(self.data['terraform']['resource_changes'][0]))
        with self.assertRaises(InputError):self.run_data()
    def test_deny_wildcard_is_not_allow_wildcard(self):
        plan(self.data,3)['after']['policy']=json.dumps({'Statement':[{'Effect':'Deny','Action':'*','Resource':'*'}]})
        self.assertNotIn('TF-IAM',self.rules())
    def test_iam_complements_require_semantic_review(self):
        plan(self.data,3)['after']['policy']=json.dumps({'Statement':[{'Effect':'Allow','NotAction':'iam:*','Resource':'*'}]})
        with self.assertRaises(InputError):self.run_data()
    def test_subprocess_import_alias(self):
        self.data['python']='from subprocess import run as call_it\ncall_it("echo demo", shell=True)\n'
        self.assertIn('PY-SHELL',self.rules())
    def test_python_strings_are_not_ast_calls(self):
        self.data['python']='text = "subprocess.run(value, shell=True)"\n'
        self.assertNotIn('PY-SHELL',self.rules())
    def test_python_syntax_error_is_not_clean(self):
        self.data['python']='def broken(:\n'
        with self.assertRaises(InputError):self.run_data()
    def test_credential_match_is_omitted_from_reports(self):
        change(self.data,'SECRET-TOKEN');report=self.run_data();serialized=safe_json(report)+safe_json(sarif(report))
        self.assertNotIn(FAKE_TOKEN,serialized);self.assertIn('SECRET-TOKEN',serialized)
    def test_current_exact_exception_is_visible(self):
        change(self.data,'KUB-IMAGE');r=self.run_data();f=r['findings'][0];apply_exceptions(r['findings'],[{'fingerprint':f['fingerprint'],'owner':'team','reason':'temporary compatibility','expires':'2026-10-30'}],AS_OF)
        self.assertTrue(f['suppressed']);self.assertEqual(sarif(r)['runs'][0]['results'][0]['suppressions'][0]['kind'],'external')
    def test_expired_exception_fails(self):
        change(self.data,'KUB-IMAGE');r=self.run_data()
        with self.assertRaises(InputError):apply_exceptions(r['findings'],[{'fingerprint':r['findings'][0]['fingerprint'],'owner':'team','reason':'old','expires':'2026-10-29'}],AS_OF)
    def test_stale_exception_fails(self):
        with self.assertRaises(InputError):apply_exceptions([],[{'fingerprint':'a'*64,'owner':'team','reason':'stale','expires':'2026-11-01'}],AS_OF)
    def test_unknown_security_values_cannot_be_waived(self):
        change(self.data,'TF-UNKNOWN');r=self.run_data()
        with self.assertRaises(InputError):apply_exceptions(r['findings'],[{'fingerprint':r['findings'][0]['fingerprint'],'owner':'team','reason':'unknown','expires':'2026-11-01'}],AS_OF)
    def test_same_inputs_produce_identical_report(self):
        change(self.data,'KUB-IMAGE');self.assertEqual(safe_json(self.run_data()),safe_json(self.run_data()))
    def test_boolean_manifest_version_rejected(self):
        p=self.root/'manifest.json';m=json.loads(p.read_text());m['schema_version']=True;p.write_text(json.dumps(m))
        with self.assertRaises(InputError):scan(self.root,AS_OF)
    def test_duplicate_manifest_paths_rejected(self):
        p=self.root/'manifest.json';m=json.loads(p.read_text());m['source_files'].append(m['source_files'][0]);p.write_text(json.dumps(m))
        with self.assertRaises(InputError):scan(self.root,AS_OF)
    def test_empty_terraform_scope_rejected(self):
        self.data['terraform']['resource_changes']=[]
        with self.assertRaises(InputError):self.run_data()


if __name__=='__main__':unittest.main()
