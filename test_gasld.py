"""Independent controlled Git scenarios. Run: python3 -m unittest -v test_gasld.py"""
import gzip
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile
import main as g
import research
S='RESEARCH_SECRET_'+'A1B2C3D4'*4
T='RESEARCH_SECRET_'+'Z9Y8X7W6'*4

class Lab:
    def __init__(self, root):
        self.path=Path(root)/'repo';self.path.mkdir();self.n=0
        self.git('init','-b','main');self.git('config','user.name','Lab');self.git('config','user.email','lab@example.invalid');self.git('config','gc.auto','0')
    def git(self,*args,env=None):
        return subprocess.run(['git','-C',str(self.path),*args],capture_output=True,text=True,check=True,env=env).stdout.strip()
    def commit(self,files,stamp=None):
        for name,data in files.items():
            p=self.path/name
            if data is None:
                if p.exists():p.unlink()
            else:
                p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data.encode() if isinstance(data,str) else data)
        self.git('add','-A');self.n+=1
        env=os.environ.copy();env['GIT_AUTHOR_DATE']=env['GIT_COMMITTER_DATE']=stamp or f'2025-01-{self.n:02d}T12:00:00+00:00'
        self.git('commit','--allow-empty','-m',f'Step {self.n}',env=env)
        return self.git('rev-parse','HEAD')
    def scan(self,**kwargs):
        params=dict(scope='all',max_blob_size=g.MAX_BLOB_DEFAULT,include_binary_strings=True,object_budget=0,max_commits=0,content_weights=g.CONTENT_WEIGHTS_DEFAULT,lineage_weights=g.LINEAGE_WEIGHTS_DEFAULT,risk_weights=g.RISK_WEIGHTS_DEFAULT,lineage_threshold=.70,rotation_threshold=.82)
        params.update(kwargs);e=g.Engine(g.GitRepo(self.path),**params);g.run_engine(e)
        return e,e.report(str(self.path),[],g.now_iso(),0,False,None)

class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.lab=Lab(self.tmp.name)
    def events(self,r):return [e for s in r['secret_identities'] for e in s['lifecycle']]
    def test_full_four_commit_lifecycle(self):
        for v in [f'API_KEY="{S}"\nDEBUG=false',f'API_KEY="{S}"\nDEBUG=true','DEBUG=true',None]:self.lab.commit({'config.env':v})
        _,r=self.lab.scan()
        self.assertEqual([e['event'] for e in self.events(r)],['introduction','persistence','secret_removed','file_deleted_after_removal'])
        self.assertEqual(r['statistics']['unique_secrets'],1);self.assertEqual(r['statistics']['occurrences'],2);self.assertEqual(r['io_accounting']['blob_reads_total'],3)
    def test_unreachable_is_historical(self):
        self.lab.commit({'base':'initial'});self.lab.git('checkout','-b','discard');self.lab.commit({'a.env':f'API_KEY="{S}"'})
        blob=self.lab.git('rev-parse','HEAD:a.env');self.lab.git('checkout','main');self.lab.git('branch','-D','discard')
        e,r=self.lab.scan(scope='unreachable')
        self.assertFalse(e.objects[blob].reachable);self.assertTrue(e.objects[blob].historical);self.assertEqual(r['statistics']['unique_secrets'],1)
    def test_detached_head_reachable(self):
        self.lab.commit({'base':'x'});self.lab.git('checkout','--detach');self.lab.commit({'a.env':f'API_KEY="{S}"'})
        blob=self.lab.git('rev-parse','HEAD:a.env');e,_=self.lab.scan();self.assertTrue(e.objects[blob].reachable)
    def test_standalone_blob_unknown(self):
        self.lab.commit({'base':'x'})
        blob=subprocess.run(['git','-C',str(self.lab.path),'hash-object','-w','--stdin'],input=f'API_KEY="{S}"',capture_output=True,text=True,check=True).stdout.strip()
        e,r=self.lab.scan();self.assertFalse(e.objects[blob].historical);self.assertEqual(r['prioritized_findings'][0]['path'],'<unknown>');self.assertIsNone(r['secret_identities'][0]['first_observed'])
    def test_current_scope_no_false_removal(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.commit({'a.env':'clean'});self.lab.commit({'a.env':'latest clean','b.env':f'API_KEY="{S}"'})
        _,r=self.lab.scan(scope='current');self.assertNotIn('secret_removed',[e['event'] for e in self.events(r)]);self.assertTrue(r['uncertain_transitions'])
    def test_size_limit_no_false_removal(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.commit({'a.env':'x'*2000+f'\nAPI_KEY="{S}"'})
        _,r=self.lab.scan(max_blob_size=100);self.assertNotIn('secret_removed',[e['event'] for e in self.events(r)]);self.assertTrue(r['uncertain_transitions'])
    def test_exact_rename_then_delete(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.commit({'a.env':None,'b.env':f'API_KEY="{S}"'});self.lab.commit({'b.env':'clean'});self.lab.commit({'b.env':None})
        _,r=self.lab.scan();events=[e['event'] for e in self.events(r)]
        self.assertIn('renamed',events);self.assertIn('file_deleted_after_removal',events);self.assertNotIn('file_deleted',events);self.assertEqual(r['propagation_edges'][0]['source_path'],'a.env')
    def test_edited_rename_and_copy(self):
        body=f'API_KEY="{S}"\n'+'setting=true\n'*15
        self.lab.commit({'a.env':body});self.lab.commit({'a.env':None,'b.env':body+'extra=true\n'});self.lab.commit({'c.env':body+'extra=true\n'})
        _,r=self.lab.scan();kinds={e['kind'] for e in r['propagation_edges']};self.assertIn('renamed',kinds);self.assertIn('copied',kinds)
    def test_copy_into_existing_file(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"','b.env':'clean'});self.lab.commit({'b.env':f'API_KEY="{S}"'})
        _,r=self.lab.scan();self.assertTrue(any(e['kind']=='possible_copy' for e in r['propagation_edges']))
    def test_equal_timestamp_ancestry_order(self):
        stamp='2025-01-01T12:00:00+00:00';a=self.lab.commit({'a.env':f'API_KEY="{S}"'},stamp);b=self.lab.commit({'a.env':'clean'},stamp)
        e,r=self.lab.scan();self.assertLess(e.commit_order.index(a),e.commit_order.index(b));self.assertEqual([x['event'] for x in self.events(r)],['introduction','secret_removed'])
    def test_commit_limit_boundary(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.commit({'a.env':f'API_KEY="{S}"\nDEBUG=true'})
        _,r=self.lab.scan(max_commits=1);self.assertEqual(self.events(r)[0]['event'],'first_observed')
    def test_merge_parent_evidence(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.git('checkout','-b','side');self.lab.commit({'a.env':'clean'});self.lab.git('checkout','main');parent=self.lab.commit({'other':'x'})
        self.lab.git('merge','--no-ff','side','-m','Merge');merge=self.lab.git('rev-parse','HEAD');_,r=self.lab.scan()
        removals=[e for e in self.events(r) if e['event']=='secret_removed' and e['commit']==merge];self.assertEqual([e['parent_commit'] for e in removals],[parent])
    def test_pack_invariance(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.commit({'a.env':'clean'});_,a=self.lab.scan();self.lab.git('repack','-ad');_,b=self.lab.scan()
        self.assertEqual(a['statistics']['unique_secrets'],b['statistics']['unique_secrets']);self.assertEqual([x['final_risk'] for x in a['prioritized_findings']],[x['final_risk'] for x in b['prioritized_findings']]);self.assertTrue(b['repository']['state_counts']['packed'])
    def test_binary_zip_gzip(self):
        raw=f'API_KEY="{S}"'.encode();z=io.BytesIO()
        with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as f:f.writestr('../../never-written.env',raw)
        self.lab.commit({'blob.bin':b'\0'+raw,'config.zip':z.getvalue(),'config.gz':gzip.compress(raw)});_,r=self.lab.scan()
        self.assertEqual(r['statistics']['unique_secrets'],1);self.assertEqual(r['statistics']['occurrences'],3);self.assertTrue(any('!gzip' in d['artifact'] for d in r['secret_detections']));self.assertFalse(r['coverage']['complete_text_scan']);self.assertFalse((Path(self.tmp.name)/'never-written.env').exists())
    def test_whitespace_identity_and_multiple_matches(self):
        self.lab.commit({'a.env':'password="abc def ghi"\npassword="abcdefghi"\npassword="abc def ghi"'});_,r=self.lab.scan()
        self.assertEqual(r['statistics']['unique_secrets'],2);self.assertEqual(len(r['secret_detections']),3);self.assertNotEqual(g.fingerprint('abc def ghi'),g.fingerprint('abcdefghi'))
    def test_confidence_threshold(self):
        self.lab.commit({'a.env':'password="example-placeholder"'});_,a=self.lab.scan(min_confidence=0);_,b=self.lab.scan(min_confidence=.9)
        self.assertGreater(a['statistics']['unique_secrets'],b['statistics']['unique_secrets'])
    def test_budget_accounting(self):
        for i in range(4):self.lab.commit({'a.env':f'API_KEY="{S}"\nDEBUG={i}'})
        _,r=self.lab.scan(object_budget=1);self.assertEqual(r['io_accounting']['blob_reads_total'],1);self.assertEqual(r['statistics']['objects_scanned'],1)
    def test_open_world_evaluation(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"\nAPI_KEY="{T}"'});_,r=self.lab.scan();ev=g.evaluate_report(r,{'items':[{'value':S,'expected_secret':True}]})
        self.assertIsNone(ev['precision']);self.assertIsNone(ev['f1']);self.assertEqual(len(ev['unjudged_detections']),1)
        ev=g.evaluate_report(r,{'complete':True,'unlisted_policy':'negative','items':[{'value':S}]});self.assertEqual(ev['fp'],1);self.assertEqual(ev['precision'],.5)
    def test_ablation_same_detector(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.commit({'b.env':f'API_KEY="{S}"'});reports=[self.lab.scan(model=m)[1] for m in 'ABCDE']
        self.assertEqual({r['statistics']['unique_secrets'] for r in reports},{1});self.assertFalse(reports[0]['lineage_edges']);self.assertFalse(reports[0]['propagation_edges']);self.assertTrue(reports[-1]['propagation_edges'])
    def test_invalid_weights(self):
        for spec in ['content=-1','content=nan','content=inf','content=0','content=1,content=1']:
            with self.assertRaises(Exception):g.parse_weights(spec,('content',))
    def test_bare_repo(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});bare=Path(self.tmp.name)/'bare.git';subprocess.run(['git','clone','--bare',str(self.lab.path),str(bare)],check=True,capture_output=True)
        self.assertEqual(research.scan(bare)['statistics']['unique_secrets'],1)
    def test_cli_json_redaction(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});out=Path(self.tmp.name)/'report.json'
        cp=subprocess.run([os.sys.executable,str(Path(g.__file__)),'--repo',str(self.lab.path),'--format','json','--output',str(out)],capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(cp.stdout)['schema'],'gasld-report-v2');self.assertNotIn(S,cp.stdout);self.assertNotIn(S,cp.stderr)
    def test_ref_snapshot_transition(self):
        self.lab.commit({'base':'x'});self.lab.git('checkout','-b','temporary');self.lab.commit({'a.env':f'API_KEY="{S}"'})
        _,before=self.lab.scan();self.lab.git('checkout','main');self.lab.git('branch','-D','temporary');_,after=self.lab.scan()
        changes=g.compare_snapshots(before,after)
        self.assertEqual(changes['removed_refs'][0]['ref'],'refs/heads/temporary');self.assertTrue(changes['became_unreachable'])
    def test_replacement_is_not_confirmed_rotation(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.commit({'a.env':f'API_KEY="{T}"'})
        _,r=self.lab.scan();kinds={e['event'] for e in self.events(r)}
        self.assertIn('possible_credential_replacement',kinds);self.assertNotIn('credential_modified_or_rotated',kinds)
        ev=g.evaluate_report(r,{'items':[{'value':S},{'value':T}],'identity_pairs':[{'a':g.fingerprint(S),'b':g.fingerprint(T),'same_family':False}]})
        self.assertEqual(ev['identity_correlation']['tn'],1)
    def test_ambiguous_copy_source(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"','b.env':f'API_KEY="{S}"'});self.lab.commit({'c.env':f'API_KEY="{S}"'})
        _,r=self.lab.scan();self.assertFalse(r['propagation_edges']);self.assertTrue(any(e['reason']=='ambiguous_lineage_source' for e in r['uncertain_transitions']))
    def test_unread_large_blobs_no_false_similarity(self):
        self.lab.commit({'a.env':'X'*3000});self.lab.commit({'a.env':'Y'*3000})
        _,r=self.lab.scan(max_blob_size=100);self.assertFalse(r['lineage_edges'])
    def test_ranking_and_structural_metrics(self):
        a,b=g.fingerprint(S),g.fingerprint(T)
        result=g.ranking_metrics([a,b],{a:{'relevance':0},b:{'relevance':3}})
        self.assertEqual(result['metrics']['1']['precision_at_k'],0);self.assertLess(result['metrics']['5']['ndcg_at_k'],1)
        result=g.structured_metrics([{'path':'a'},{'path':'extra'}],[{'path':'a'}],('path',),False)
        self.assertIsNone(result['precision']);self.assertEqual(result['unjudged_predictions'],1)
    def test_worktree_packed_storage(self):
        self.lab.commit({'a.env':f'API_KEY="{S}"'});self.lab.git('repack','-ad')
        wt=Path(self.tmp.name)/'worktree';self.lab.git('worktree','add','--detach',str(wt))
        r=research.scan(wt);self.assertTrue(r['repository']['state_counts']['packed'])
    def test_calibration_holdout(self):
        def pair(name,split,prefix):
            fps=[g.fingerprint(prefix+str(i)) for i in range(2)];findings=[]
            for i,fp in enumerate(fps):
                row={'fingerprint':fp};row.update({v:float(i) for v in research.COMPONENTS.values()});findings.append(row)
            rp=Path(self.tmp.name)/(name+'-report.json');tp=Path(self.tmp.name)/(name+'-truth.json')
            research.dump(rp,{'repository_path':name,'prioritized_findings':findings});research.dump(tp,{'dataset_id':name,'split':split,'items':[{'fingerprint':fp,'relevance':i*3} for i,fp in enumerate(fps)]});return str(rp),str(tp)
        train=pair('train','train','AAA');test=pair('test','test','ZZZ');output=Path(self.tmp.name)/'config.json'
        result=research.calibrate([train],[test],output,trials=5);self.assertAlmostEqual(sum(result['risk_weights'].values()),1);self.assertEqual(result['held_out_ndcg_at_5'],1)
        truth=json.loads(Path(test[1]).read_text());truth['dataset_id']='train';research.dump(test[1],truth)
        with self.assertRaises(ValueError):research.calibrate([train],[test],output,trials=5)

if __name__=='__main__':unittest.main(verbosity=2)
