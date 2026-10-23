"""Inspect the open SOC-MLD Zenodo dataset and print schema, not records."""
import io, zipfile, hashlib, urllib.request, os, re
import pandas as pd
URL='https://zenodo.org/records/23116148/files/SOC-MLD-v1.zip?download=1'
MD5='764ca570a35753a90f6ac3046750c716'
print('SOURCE',URL,flush=True)
req=urllib.request.Request(URL,headers={'User-Agent':'AcademicResearch/1.0 Mozilla/5.0'})
with urllib.request.urlopen(req,timeout=180) as response:
    data=response.read()
print('downloaded_bytes',len(data),'MD5',hashlib.md5(data).hexdigest(),flush=True)
assert hashlib.md5(data).hexdigest()==MD5, 'archive checksum mismatch'
with zipfile.ZipFile(io.BytesIO(data)) as z:
    for info in z.infolist():
        if info.is_dir(): continue
        print('FILE',info.filename,'size',info.file_size,flush=True)
        if re.search(r'\.(csv|parquet|json|md)$',info.filename,re.I):
            if info.file_size>30_000_000:continue
            if '../' in info.filename or info.filename.startswith('/'):raise RuntimeError('unsafe path')
            try:
                content=z.read(info.filename)
                suffix=os.path.splitext(info.filename)[1].lower()
                if suffix=='.csv':
                    df=pd.read_csv(io.BytesIO(content),nrows=4)
                    print('SCHEMA',info.filename,'COLS',list(df.columns),'FIRSTROWS',df.head(2).to_json(orient='records')[:1600],flush=True)
                elif suffix=='.parquet':
                    df=pd.read_parquet(io.BytesIO(content)).head(4)
                    print('SCHEMA',info.filename,'COLS',list(df.columns),'FIRSTROWS',df.head(2).to_json(orient='records')[:1600],flush=True)
                elif suffix in ('.md','.json') and re.search(r'(feature|description|readme|schema|data_dictionary)',info.filename,re.I):
                    print('DOC',info.filename,content[:5000].decode('utf-8','replace'),flush=True)
            except Exception as e:print('INSPECT_ERROR',info.filename,type(e).__name__,str(e)[:250],flush=True)
