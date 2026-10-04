"""Scale test: replicates alerts/cases N times in a temp dir and times the full analytics run. Usage: python scale.py 40"""
import pandas as pd, subprocess, sys, os, shutil, tempfile, time, resource
n = int(sys.argv[1]) if len(sys.argv) > 1 else 40; d = tempfile.mkdtemp()
A = pd.read_csv('alerts.csv'); C = pd.read_csv('cases.csv')
big_a = pd.concat([A.assign(alert_id=A.alert_id + f'-{i}', case_id=A.case_id.where(A.case_id.isna(), A.case_id + f'-{i}')) for i in range(n)])
big_c = pd.concat([C.assign(case_id=C.case_id + f'-{i}', source_alert_id=C.source_alert_id + f'-{i}') for i in range(n)])
big_a.to_csv(f'{d}/alerts.csv', index=False); big_c.to_csv(f'{d}/cases.csv', index=False)
for f in ('assets.csv', 'entities.csv', 'satsa.py'): shutil.copy(f, d)
t = time.time(); r = subprocess.run([sys.executable, 'satsa.py'], cwd=d, capture_output=True, text=True)
print(f"alerts={len(big_a):,} cases={len(big_c):,} ok={r.returncode == 0} time={time.time() - t:.0f}s peak_mem={resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024}MB")
if r.returncode: print(r.stderr[-400:])
shutil.rmtree(d)
