"""ICASSP 2027: coverage-aware triage on verified public cyber-range data.
Run on a clean Python environment with pandas, numpy, scikit-learn.
This is experimental analysis, not a deployed SOC performance estimate.
"""
import io,zipfile,hashlib,urllib.request,json,warnings
from collections import defaultdict
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.metrics import f1_score,balanced_accuracy_score, brier_score_loss

URL='https://zenodo.org/records/23116148/files/SOC-MLD-v1.zip?download=1'
MD5='764ca570a35753a90f6ac3046750c716'
SEEDS=(11,23,37,51,73,101,109,131,149,173)
RATES=(0.0,.25,.5,.75,1.0)
BUDGETS=(.1,.2,.3)
GROUPS={
 'network':['f_flow_duration','f_flow_pkts_total','f_flow_bytes_total','f_tcp_syn','f_tcp_ack','f_tcp_fin','f_tcp_rst'],
 'flow':['f_session_req_count','f_session_duration','f_session_unique_paths','f_session_error_count','f_session_req_rate'],
 'http':['f_has_sqli','f_has_xss','f_has_lfi','f_has_cmd','f_has_ssrf','f_has_traversal','f_is_scanner_ua','f_query_len','f_path_depth','f_has_encoded','f_has_sql_comment',
         'f_req_count_1s','f_req_rate_1s','f_req_count_10s','f_req_rate_10s','f_req_count_60s','f_req_rate_60s','f_error_ratio_10s','f_unique_paths_10s','f_404_count_10s','f_404_count_60s'],
 'suricata':['f_suricata_alerts_60s','f_suricata_high_sev_60s','f_suricata_unique_sigs','f_flow_pkts_out_60s','f_flow_pkts_in_60s','f_flow_bytes_out_60s','f_flow_syn_ratio','f_flow_count_60s']
}
print('Downloading benchmark:',URL,flush=True)
req=urllib.request.Request(URL,headers={'User-Agent':'IEEE benchmark research reproducibility'})
with urllib.request.urlopen(req,timeout=180) as response: content=response.read()
assert hashlib.md5(content).hexdigest()==MD5
print('Verified MD5',MD5,flush=True)
with zipfile.ZipFile(io.BytesIO(content)) as z:
    file='SOC-MLD-v1.0/dataset/curated/dataset.csv'
    df=pd.read_csv(io.BytesIO(z.read(file)))
features=sum((GROUPS[k] for k in GROUPS),[])
assert len(features)==41 and len(set(features))==41
assert set(features)==set(x for x in df.columns if x.startswith('f_'))
assert len(df)==6006
raw_labels=df.label.astype(str).str.upper().str.strip()
assert 'NORMAL' in set(raw_labels)
y=(raw_labels!='NORMAL').astype(int).values
groups=df.attack_instance_id.astype(str).values
X=df[features].replace([np.inf,-np.inf],np.nan).apply(pd.to_numeric,errors='coerce').astype(float)
assert X.isna().mean().max()<0.01
print('AUDIT',json.dumps({'rows':len(df),'attack_rows':int(y.sum()),'normal_rows':int((1-y).sum()),
 'groups':len(set(groups)),'features':len(features),
 'mixed_label_groups':int((pd.DataFrame({'group':groups,'y':y}).groupby('group').y.nunique()>1).sum()),
 'dataset_md5':MD5,'mean_original_missing':float(X.isna().mean().mean())}),flush=True)
records=[]
for seed in SEEDS:
    s=GroupShuffleSplit(n_splits=1,test_size=.25,random_state=seed)
    train_idx,test_idx=next(s.split(X,y,groups))
    assert not(set(groups[train_idx])&set(groups[test_idx]))
    if len(set(y[train_idx]))<2 or len(set(y[test_idx]))<2:
        print('SKIP_SEED_CLASS_ABSENT',seed,flush=True)
        continue
    model=make_pipeline(SimpleImputer(strategy='median',keep_empty_features=True),StandardScaler(),
                     LogisticRegression(max_iter=1500,class_weight='balanced',random_state=seed))
    model.fit(X.iloc[train_idx],y[train_idx])
    gs=groups[test_idx]
    ys=y[test_idx]
    unique=np.unique(gs)
    for rate in RATES:
        rng=np.random.default_rng(seed+int(rate*10000)+3026)
        k=int(round(rate*len(unique)))
        selected=set(rng.choice(unique,size=k,replace=False)) if k else set()
        outage_names=['network','flow','http','suricata']
        outage_group={g:outage_names[int(rng.integers(4))] for g in selected}
        Xt=X.iloc[test_idx].copy()
        coverage=np.ones(len(Xt),dtype=float)
        for g,mod in outage_group.items():
            mask=gs==g
            Xt.loc[mask,GROUPS[mod]]=np.nan
            coverage[mask]=.75
        p=model.predict_proba(Xt)[:,1]
        conf=1.0-np.maximum(p,1-p)
        pred=(p>=.5).astype(int)
        fns=(ys==1)&(pred==0)
        for budget in BUDGETS:
            k_review=int(round(len(ys)*budget))
            risks={'confidence_only':conf,
                   'coverage_aware':conf+.5*(1-coverage),
                   'coverage_only':1-coverage}
            for policy,score in risks.items():
                ranks=np.argsort(-score,kind='stable')
                review=np.zeros(len(ys),dtype=bool)
                review[ranks[:k_review]]=True
                records.append({'seed':seed,'outage_fraction':rate,'budget':budget,'policy':policy,
                    'n_test':len(ys),'test_attack_rows':int((ys==1).sum()),'review_n':int(review.sum()),
                    'unreviewed_fn':int((fns&~review).sum()),
                    'fn_per_100_attacks':float(100*(fns&~review).sum()/max(1,(ys==1).sum())),
                    'f1_all':float(f1_score(ys,pred,zero_division=0)),
                    'balanced_accuracy':float(balanced_accuracy_score(ys,pred)),
                    'brier':float(brier_score_loss(ys,p)),
                    'accepted_error_rate':float(((pred!=ys)&~review).sum()/max(1,(~review).sum())),
                    'reviewed_false_negatives':int((fns&review).sum()),
                    'avg_sensor_coverage':float(coverage.mean()),
                    'group_disjoint':True})
result=pd.DataFrame(records)
print('VALID_SEEDS',int(result.seed.nunique()),flush=True)
summary=result.groupby(['outage_fraction','budget','policy']).agg(
 n_splits=('seed','nunique'),fn_mean=('fn_per_100_attacks','mean'),
 fn_sd=('fn_per_100_attacks','std'),acc_err_mean=('accepted_error_rate','mean'),
 brier_mean=('brier','mean'),f1_mean=('f1_all','mean')
 ).reset_index()
delta=[]
for (rate,budget), d in result.groupby(['outage_fraction','budget']):
    pivot=d.pivot(index='seed',columns='policy',values='fn_per_100_attacks')
    if {'coverage_aware','confidence_only'}<=set(pivot.columns):
        paired=pivot.coverage_aware-pivot.confidence_only
        delta.append({'rate':rate,'budget':budget,'paired_delta_mean':float(paired.mean()),
                      'paired_delta_sd':float(paired.std()),'seeds':len(paired),
                      'coverage_better_seeds':int((paired<0).sum()),
                      'coverage_worse_seeds':int((paired>0).sum()),
                      'tie_seeds':int((paired==0).sum())})
print('SUMMARY_JSON='+summary.to_json(orient='records',double_precision=6),flush=True)
print('PAIRED_JSON='+json.dumps(delta,separators=(',',':')),flush=True)
print('METHOD_NOTE: group-disjoint repeated holdouts, features zero-filled by baseline only where truly zero; simulated one-modality outages, no human-study claims.',flush=True)
