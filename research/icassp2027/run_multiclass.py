"""Replicable missing-telemetry multiclass attribution benchmark using SOC-MLD official split.
Training features: precisely the dataset's 41 f_* numerical features.
Never interpret test-set review as real human performance.
"""
import io,zipfile,urllib.request,hashlib,json,collections
import numpy as np,pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score,f1_score

URL='https://zenodo.org/records/23116148/files/SOC-MLD-v1.zip?download=1'
MD5='764ca570a35753a90f6ac3046750c716'
RATES=[0,.25,.5,.75,1.0]
SEEDS=[11,23,37,51,73,101,109,131,149,173]
BUDGETS=[.1,.2,.3]
GROUPS={
 'network':['f_flow_duration','f_flow_pkts_total','f_flow_bytes_total','f_tcp_syn','f_tcp_ack','f_tcp_fin','f_tcp_rst'],
 'session':['f_session_req_count','f_session_duration','f_session_unique_paths','f_session_error_count','f_session_req_rate'],
 'http':['f_has_sqli','f_has_xss','f_has_lfi','f_has_cmd','f_has_ssrf','f_has_traversal','f_is_scanner_ua','f_query_len','f_path_depth','f_has_encoded','f_has_sql_comment',
         'f_req_count_1s','f_req_rate_1s','f_req_count_10s','f_req_rate_10s','f_req_count_60s','f_req_rate_60s','f_error_ratio_10s','f_unique_paths_10s','f_404_count_10s','f_404_count_60s'],
 'ids':['f_suricata_alerts_60s','f_suricata_high_sev_60s','f_suricata_unique_sigs','f_flow_pkts_out_60s','f_flow_pkts_in_60s','f_flow_bytes_out_60s','f_flow_syn_ratio','f_flow_count_60s']
}
req=urllib.request.Request(URL,headers={'User-Agent':'SOC-MLD evaluation for academic research'})
with urllib.request.urlopen(req,timeout=180) as r: raw=r.read()
assert hashlib.md5(raw).hexdigest()==MD5
with zipfile.ZipFile(io.BytesIO(raw)) as z:
 tr=pd.read_csv(io.BytesIO(z.read('SOC-MLD-v1.0/dataset/curated/train.csv')))
 te=pd.read_csv(io.BytesIO(z.read('SOC-MLD-v1.0/dataset/curated/test.csv')))
f=sum(GROUPS.values(),[])
assert len(f)==41 and set(f)==set(c for c in tr if c.startswith('f_'))
assert not (set(tr.attack_instance_id.astype(str)) & set(te.attack_instance_id.astype(str)))
Xtr=tr[f].astype(float)
Xte=te[f].astype(float)
ytr=tr.label.astype(str).values
yte=te.label.astype(str).values
print('DATA_AUDIT',json.dumps({'md5':MD5,'train':len(tr),'test':len(te),'train_instances':tr.attack_instance_id.nunique(),'test_instances':te.attack_instance_id.nunique(),
 'train_label_count':int(tr.label.nunique()),'test_label_count':int(te.label.nunique()),
 'test_benign_n':int((te.label=='NORMAL').sum()),'test_attack_n':int((te.label!='NORMAL').sum()),
 'features':len(f)}),flush=True)
imputer=SimpleImputer(strategy='median',keep_empty_features=True)
Xtr_imputed=imputer.fit_transform(Xtr)
model=RandomForestClassifier(n_estimators=200,class_weight='balanced_subsample',random_state=2027,n_jobs=2,min_samples_leaf=2)
model.fit(Xtr_imputed,ytr)
test_inst=te.attack_instance_id.astype(str).values
unique=np.unique(test_inst)
rec=[]
for rate in RATES:
 for seed in SEEDS:
    rng=np.random.default_rng(12573+seed+int(rate*10000))
    lost=set(rng.choice(unique,size=int(round(rate*len(unique))),replace=False)) if rate>0 else set()
    selected={g:int(rng.integers(4)) for g in lost}
    X=Xte.copy()
    coverage=np.ones(len(te))
    for g,mod in selected.items():
        mask=(test_inst==g)
        X.loc[mask,GROUPS[list(GROUPS)[mod]]]=np.nan
        coverage[mask]=.75
    p=model.predict_proba(imputer.transform(X))
    pred=model.classes_[p.argmax(axis=1)]
    error=(pred!=yte)
    unc=1-p.max(axis=1)
    base=float(accuracy_score(yte,pred))
    fm=float(f1_score(yte,pred,average='macro',zero_division=0))
    for budget in BUDGETS:
      k=int(round(len(yte)*budget))
      risks={'confidence_only':unc, 'coverage_aware':unc+0.5*(1-coverage), 'coverage_first':1-coverage+1e-4*unc}
      for name,score in risks.items():
        review=np.zeros(len(te),dtype=bool)
        review[np.argsort(-score,kind='stable')[:k]]=True
        rec.append({'rate':rate,'seed':seed,'budget':budget,'method':name,'test_n':len(te),
          'review_n':int(review.sum()),'multiclass_accuracy':base,'macro_f1':fm,
          'auto_closed_wrong':int((error & ~review).sum()),
          'auto_closed_wrong_per_100_events':100*float((error & ~review).sum())/len(te),
          'reviewed_errors':int((error & review).sum()),
          'mean_coverage':float(coverage.mean()),'total_model_errors':int(error.sum())})
rows=pd.DataFrame(rec)
summary=rows.groupby(['rate','budget','method'],as_index=False).agg(
 closed_error_mean=('auto_closed_wrong_per_100_events','mean'),
 closed_error_sd=('auto_closed_wrong_per_100_events','std'),
 macro_f1_mean=('macro_f1','mean'),
 model_accuracy=('multiclass_accuracy','mean'),
 reviewed_errors=('reviewed_errors','mean')).round(6)
deltas=[]
for (rate,budget),s in rows.groupby(['rate','budget']):
 p=s.pivot(index='seed',columns='method',values='auto_closed_wrong_per_100_events')
 d=p.coverage_aware-p.confidence_only
 deltas.append({'rate':rate,'budget':budget,'mean_diff':float(d.mean()),
                'sd_diff':float(d.std()),'better_seeds':int((d<0).sum()),
                'worse_seeds':int((d>0).sum()),'tied_seeds':int((d==0).sum())})
print('MULTICLASS_SUMMARY='+summary.to_json(orient='records'),flush=True)
print('MULTICLASS_PAIRED='+json.dumps(deltas,separators=(',',':')),flush=True)
print('END_SUCCESS',flush=True)
