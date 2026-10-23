"""Public SOC-MLD benchmark: leakage-audited multiclass selective classification.
Mixed-label attack-instance groups are kept indivisible in training/test partitions.
All incidents and missingness are cyber-range observations or simulated masks.
"""
import io,zipfile,urllib.request,hashlib,json
import numpy as np,pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score

URL='https://zenodo.org/records/23116148/files/SOC-MLD-v1.zip?download=1'
MD5='764ca570a35753a90f6ac3046750c716'
SEEDS=[11,23,37,51,73,101,109,131,149,173]
RATES=[0.0,.25,.50,.75,1.0]
BUDGETS=[.1,.2,.3]
GROUPS={
 'network':['f_flow_duration','f_flow_pkts_total','f_flow_bytes_total','f_tcp_syn','f_tcp_ack','f_tcp_fin','f_tcp_rst'],
 'session':['f_session_req_count','f_session_duration','f_session_unique_paths','f_session_error_count','f_session_req_rate'],
 'http':['f_has_sqli','f_has_xss','f_has_lfi','f_has_cmd','f_has_ssrf','f_has_traversal','f_is_scanner_ua','f_query_len','f_path_depth','f_has_encoded','f_has_sql_comment','f_req_count_1s','f_req_rate_1s','f_req_count_10s','f_req_rate_10s','f_req_count_60s','f_req_rate_60s','f_error_ratio_10s','f_unique_paths_10s','f_404_count_10s','f_404_count_60s'],
 'ids':['f_suricata_alerts_60s','f_suricata_high_sev_60s','f_suricata_unique_sigs','f_flow_pkts_out_60s','f_flow_pkts_in_60s','f_flow_bytes_out_60s','f_flow_syn_ratio','f_flow_count_60s']
}
req=urllib.request.Request(URL,headers={'User-Agent':'Research evaluation of public SOC-MLD benchmark'})
with urllib.request.urlopen(req,timeout=180) as r: raw=r.read()
assert hashlib.md5(raw).hexdigest()==MD5
with zipfile.ZipFile(io.BytesIO(raw)) as z:
 df=pd.read_csv(io.BytesIO(z.read('SOC-MLD-v1.0/dataset/curated/dataset.csv')))
 otr=pd.read_csv(io.BytesIO(z.read('SOC-MLD-v1.0/dataset/curated/train.csv')))
 ote=pd.read_csv(io.BytesIO(z.read('SOC-MLD-v1.0/dataset/curated/test.csv')))
ov=set(otr.attack_instance_id.astype(str)) & set(ote.attack_instance_id.astype(str))
print('OFFICIAL_SPLIT_OVERLAP',json.dumps({'overlap_group_count':len(ov),
 'overlapping_train_rows':int(otr.attack_instance_id.astype(str).isin(ov).sum()),
 'overlapping_test_rows':int(ote.attack_instance_id.astype(str).isin(ov).sum()),
 'missing_train_id':int(otr.attack_instance_id.isna().sum()),
 'missing_test_id':int(ote.attack_instance_id.isna().sum()),
 'training_rows':len(otr),'testing_rows':len(ote)}),flush=True)
f=sum(GROUPS.values(),[])
assert len(f)==41 and set(f)=={x for x in df.columns if x.startswith('f_')}
X=df[f].apply(pd.to_numeric,errors='raise').replace([np.inf,-np.inf],np.nan)
labels=df.label.astype(str).values
groups=df.attack_instance_id.astype(str).values
classes=sorted(set(labels))
print('AUDIT',json.dumps({'rows':len(df),'features':len(f),'classes':len(classes),
 'groups':len(set(groups)),'benign_rows':int((labels=='NORMAL').sum()),
 'attack_rows':int((labels!='NORMAL').sum()),'MD5':MD5}),flush=True)
rec=[]
for seed in SEEDS:
 train_idx,test_idx=next(GroupShuffleSplit(n_splits=1,test_size=.25,random_state=seed).split(X,labels,groups))
 assert not(set(groups[train_idx]) & set(groups[test_idx]))
 model=RandomForestClassifier(n_estimators=120,min_samples_leaf=2,class_weight='balanced_subsample',n_jobs=2,random_state=seed)
 imp=SimpleImputer(strategy='median',keep_empty_features=True)
 Xtr=imp.fit_transform(X.iloc[train_idx])
 model.fit(Xtr,labels[train_idx])
 ys=labels[test_idx]
 gi=groups[test_idx]
 uniq=np.unique(gi)
 missing_train_classes=set(classes)-set(labels[train_idx])
 if missing_train_classes: print('TRAIN_CLASSES_ABSENT',seed,sorted(missing_train_classes),flush=True)
 for rate in RATES:
    rng=np.random.default_rng(12573+seed+int(rate*10000))
    absent_groups=set(rng.choice(uniq,size=int(round(rate*len(uniq))),replace=False)) if rate else set()
    absent_mod={g: list(GROUPS)[int(rng.integers(4))] for g in absent_groups}
    Xte=X.iloc[test_idx].copy()
    cover=np.ones(len(test_idx))
    for g,mod in absent_mod.items():
      mask=gi==g
      Xte.loc[mask,GROUPS[mod]]=np.nan
      cover[mask]=.75
    p=model.predict_proba(imp.transform(Xte))
    pred=model.classes_[np.argmax(p,axis=1)]
    wrong=(pred!=ys)
    conf=1.0-np.max(p,axis=1)
    f1=float(f1_score(ys,pred,labels=classes,average='macro',zero_division=0))
    for budget in BUDGETS:
      k=int(round(budget*len(ys)))
      scores={'confidence_only':conf,'coverage_aware':conf+.5*(1-cover),
              'coverage_first':(1-cover)+.0001*conf}
      for pol,s in scores.items():
        review=np.zeros(len(ys),dtype=bool)
        review[np.argsort(-s,kind='stable')[:k]]=True
        rec.append({'seed':seed,'outage':rate,'budget':budget,'policy':pol,
          'test_rows':len(ys),'test_groups':len(uniq),
          'wrong_total':int(wrong.sum()),'reviewed_errors':int((wrong&review).sum()),
          'unreviewed_errors_per100':100*float((wrong&~review).sum())/len(ys),
          'f1_macro':f1,'accuracy':float((~wrong).mean()),
          'mean_coverage':float(cover.mean())})
rows=pd.DataFrame(rec)
s=rows.groupby(['outage','budget','policy'],as_index=False).agg(
 unreviewed_error_mean=('unreviewed_errors_per100','mean'),
 unreviewed_error_sd=('unreviewed_errors_per100','std'),
 f1_mean=('f1_macro','mean'),
 accuracy_mean=('accuracy','mean'),
 review_wrong_mean=('reviewed_errors','mean'),
 n_splits=('seed','nunique')).round(5)
deltas=[]
for (rate,budget),z in rows.groupby(['outage','budget']):
    pivot=z.pivot(index='seed',columns='policy',values='unreviewed_errors_per100')
    delta=pivot.coverage_aware-pivot.confidence_only
    deltas.append({'rate':rate,'budget':budget,'mean_delta':float(delta.mean()),'sd_delta':float(delta.std()),
       'better':int((delta<0).sum()),'worse':int((delta>0).sum()),'ties':int((delta==0).sum())})
print('MULTICLASS_SUMMARY='+s.to_json(orient='records'),flush=True)
print('MULTICLASS_PAIRED='+json.dumps(deltas,separators=(',',':')),flush=True)
print('END_SUCCESS',flush=True)
