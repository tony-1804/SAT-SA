"""SAT-SA: offline supervisory analytics. Usage: python satsa.py  ->  dashboard.html + audit_log.json
Deps: pandas, numpy only. No network, no external models. Fully rule-based & explainable."""
import pandas as pd, numpy as np, json, hashlib, datetime as dt

# Configurable weights (adverse-deviation vs peers). Prototype methodology, not an official scoring system.
W = dict(orphan=.10, miss_cat=.08, drop=.08, crit_no_esc=.18, fast_close=.14, blind=.16, dur=.10, evid=.10, reason=.06, template=.10, repeat=.08, stale=.08)
META = {
 'orphan': ('Negative Space', 'Escalation', 'Escalated alerts with no case record', 'May indicate missing investigation or escalation records.'),
 'miss_cat': ('Negative Space', 'Threat Detection', 'Expected alert categories absent (peers have them)', 'May indicate detection coverage gaps for that threat type.'),
 'drop': ('Negative Space', 'Security Operations', 'Unexpected drop in alert activity (3-wk low vs own median)', 'May indicate telemetry loss or a monitoring outage.'),  # metric: (type, capability, label, why-it-matters)
 'crit_no_esc': ('Execution Gap', 'Escalation', 'High/Critical alerts closed without escalation', 'May indicate under-escalation of serious alerts.'),
 'fast_close': ('Execution Gap', 'Investigation', 'High/Critical alerts closed within minutes', 'May indicate alerts acknowledged but not meaningfully investigated.'),
 'blind': ('Negative Space', 'Threat Detection', 'Critical assets with no telemetry', 'May indicate monitoring blind spots on critical systems.'),
 'dur': ('Execution Gap', 'Operational Discipline', 'Median case duration', 'May indicate slow investigation or weak workflow discipline.'),
 'evid': ('Execution Gap', 'Governance and Oversight', 'Cases with no evidence attached', 'May indicate closures not supported by evidence.'),
 'reason': ('Execution Gap', 'Governance and Oversight', 'Closed cases with no closure reason', 'May indicate incomplete documentation.'),
 'template': ('Execution Gap', 'Investigation', 'Cases with repeated/template notes', 'May indicate superficial or copy-paste review.'),
 'repeat': ('Execution Gap', 'Incident Response', 'Alerts in repeat rule+asset clusters', 'May indicate no root-cause remediation.'),
 'stale': ('Execution Gap', 'Security Operations', 'Alerts left open', 'May indicate backlog or ignored alerts.')}
F = ['alerts.csv', 'cases.csv', 'assets.csv', 'entities.csv']
A = pd.read_csv('alerts.csv'); C = pd.read_csv('cases.csv')
for d, cs in ((A, ['timestamp', 'closed_at']), (C, ['detected_at', 'closed_at'])):
    for c in cs: d[c] = pd.to_datetime(d[c], format='mixed')
AS = pd.read_csv('assets.csv'); EN = pd.read_csv('entities.csv').set_index('entity_id')
crit_a = set(AS[AS.criticality == 'Critical'].asset_id)
hi = A.severity.isin(['High', 'Critical']); closed = A.status.str.startswith('Closed')
A['hrs'] = (A.closed_at - A.timestamp).dt.total_seconds() / 3600
A['noesc'] = hi & closed; A['fast'] = hi & closed & (A.hrs < .25)
A['rep'] = A.groupby(['entity_id', 'rule_id', 'asset_id']).alert_id.transform('count')
C['dur'] = (C.closed_at - C.detected_at).dt.total_seconds() / 3600
C['tpl'] = C.groupby(['entity_id', 'note_hash']).case_id.transform('count') >= 5
Cc = C[C.status == 'Closed']

M = pd.DataFrame(index=EN.index)
M['crit_no_esc'] = A[hi].groupby('entity_id').noesc.mean(); M['fast_close'] = A[hi].groupby('entity_id').fast.mean()
seen = A.groupby('entity_id').asset_id.agg(set)
M['blind'] = [np.mean([a not in seen[e] for a in AS[(AS.entity_id == e) & (AS.criticality == 'Critical')].asset_id]) for e in M.index]
M['dur'] = C.groupby('entity_id').dur.median(); M['evid'] = C.groupby('entity_id').evidence_attached.apply(lambda s: (s == 'No').mean())
M['reason'] = Cc.groupby('entity_id').closure_reason.apply(lambda s: s.isna().mean())
M['template'] = C.groupby('entity_id').tpl.mean(); M['repeat'] = (A.rep >= 6).groupby(A.entity_id).mean()
M['stale'] = (A.status == 'Open').groupby(A.entity_id).mean(); cs = A.groupby(['entity_id', 'category']).size().unstack(fill_value=0); cs = cs.div(cs.sum(axis=1), axis=0)
EXP = [c for c in cs if (cs[c] > .02).mean() >= .75]; M['miss_cat'] = (cs[EXP] < .02).mean(axis=1)
WK = A.groupby(['entity_id', A.timestamp.dt.to_period('W')]).size().unstack(fill_value=0).iloc[:, 1:-1]
M['drop'] = (1 - WK.T.rolling(3).mean().min() / WK.median(axis=1)).clip(0, 1); M = M.fillna(0)
_e = A[A.status == 'Escalated to Case'].assign(o=lambda d: ~d.alert_id.isin(C.source_alert_id)); M['orphan'] = _e.groupby('entity_id').o.mean().reindex(M.index).fillna(0)
med = M.median(); SEC = EN.sector       # peers = same sector if >=3 entities, else all entities
grp = {e: ([x for x in M.index if SEC[x] == SEC[e]] if (SEC == SEC[e]).sum() >= 3 else list(M.index)) for e in M.index}
def _pm(e): m = M.loc[grp[e]]; d = m.median(); return d, (m - d).abs().median() * 1.4826 + 1e-9
PM = {e: _pm(e) for e in M.index}
Z = pd.DataFrame({e: ((M.loc[e] - PM[e][0]) / PM[e][1]).clip(0, 3) for e in M.index}).T                      # robust peer z-score, adverse direction only
score = sum(W[k] * Z[k] / 3 for k in W) / sum(W.values()) * 100
lvl = lambda s: 'HIGH' if s >= 38 else 'MEDIUM' if s >= 12 else 'LOW'

def rec(df, cols, n=6): return df[cols].head(n).astype(str).to_dict('records')
def evidence(k, e):
    a, c = A[A.entity_id == e], C[C.entity_id == e]; ac = ['alert_id', 'timestamp', 'rule_name', 'severity', 'asset_id', 'status']
    cc = ['case_id', 'severity', 'analyst_id', 'status', 'evidence_attached', 'note_hash']
    if k == 'crit_no_esc': return rec(a[a.noesc].sort_values('severity', ascending=False), ac)
    if k == 'fast_close': return rec(a[a.fast].sort_values('hrs'), ac + ['hrs'])
    if k == 'blind': return [dict(asset_id=x, note='No alerts/telemetry in period') for x in AS[(AS.entity_id == e) & (AS.criticality == 'Critical') & ~AS.asset_id.isin(seen[e])].asset_id[:6]]
    if k == 'dur': return rec(c.sort_values('dur', ascending=False), cc + ['dur'])
    if k == 'evid': return rec(c[c.evidence_attached == 'No'], cc)
    if k == 'reason': return rec(c[(c.status == 'Closed') & c.closure_reason.isna()], cc)
    if k == 'template': return rec(c[c.tpl].sort_values('note_hash'), cc)
    if k == 'repeat': return rec(a[a.rep >= 6].sort_values('rep', ascending=False), ac + ['rep'])
    if k == 'orphan': return rec(a[(a.status == 'Escalated to Case') & ~a.alert_id.isin(C.source_alert_id)], ac)
    if k == 'miss_cat': return [dict(category=c, entity_share=f"{cs.loc[e, c]:.1%}", peer_median_share=f"{cs[c].median():.1%}") for c in EXP if cs.loc[e, c] < .02]
    if k == 'drop': return [dict(week=str(w), alerts=int(n), own_median=int(WK.loc[e].median())) for w, n in WK.loc[e].items()]
    return rec(a[a.status == 'Open'].sort_values('timestamp'), ac)

ents = []
for e in M.index:
    fs = []
    for k in sorted(W, key=lambda k: -Z.loc[e, k] * W[k]):
        if Z.loc[e, k] >= 1.5:
            t, cap, lab, why = META[k]; v = M.loc[e, k]
            fs.append(dict(key=k, type=t, capability=cap, title=lab, value=round(float(v), 3), peer_median=round(float(PM[e][0][k]), 3), z=round(float(Z.loc[e, k]), 2),
                           text=f"{lab}: {v:.1%} vs peer median {PM[e][0][k]:.1%}." if k != 'dur' else f"{lab}: {v:.0f}h vs peer median {PM[e][0][k]:.0f}h.", why=why, evidence=evidence(k, e)))
    wk = A[A.entity_id == e].groupby(A.timestamp.dt.to_period('W')).size().tolist()
    ents.append(dict(id=e, name=EN.loc[e, 'name'], sector=EN.loc[e, 'sector'], alerts=int((A.entity_id == e).sum()), cases=int((C.entity_id == e).sum()),
                     peer={k: round(float(PM[e][0][k]), 3) for k in W}, peer_group=('sector: ' + SEC[e]) if len(grp[e]) < len(M) else 'all entities', score=round(float(score[e]), 1), level=lvl(score[e]), findings=fs, weekly=wk, metrics={k: round(float(M.loc[e, k]), 3) for k in W}))
ents.sort(key=lambda x: -x['score'])

# alert priority queue: not just severity - pattern, speed, criticality and entity context matter
sc = A.severity.map({'Low': 0, 'Medium': 8, 'High': 16, 'Critical': 24}) + (A.rep >= 6) * 15 + A.fast * 20 + A.noesc * 12 + A.asset_id.isin(crit_a) * 8 + A.entity_id.map(score) * .2
A['prio'] = sc; q = A.sort_values('prio', ascending=False).head(40)
def why(r): return ', '.join(x for x, f in [('repeat pattern', r.rep >= 6), ('closed in minutes', r.fast), ('high/critical not escalated', r.noesc), ('critical asset', r.asset_id in crit_a)] if f) or 'severity'
queue = [dict(alert_id=r.alert_id, entity=EN.loc[r.entity_id, 'name'], severity=r.severity, rule=r.rule_name, asset=r.asset_id, status=r.status, priority=round(float(r.prio), 1), reasons=why(r)) for r in q.itertuples()]


# unsupervised "unknown indicator" detector: entity-weeks that deviate from the entity's OWN normal behaviour
A['wk'] = A.timestamp.dt.to_period('W')
WF = A.groupby(['entity_id', 'wk']).agg(alerts=('alert_id', 'size'), fast=('fast', 'mean'), noesc=('noesc', 'mean'), open=('status', lambda s: (s == 'Open').mean()), hrs=('hrs', 'median')).reset_index().fillna(0)
WF = WF[(WF.wk != WF.wk.min()) & (WF.wk != WF.wk.max())].copy(); FE = ['alerts', 'fast', 'noesc', 'open', 'hrs']
md = WF.groupby('entity_id')[FE].transform('median'); mad = ((WF[FE] - md).abs().groupby(WF.entity_id).transform('median') * 1.4826).clip(lower=pd.Series(dict(alerts=5, fast=.03, noesc=.03, open=.03, hrs=3)), axis=1)
Zw = (WF[FE] - md) / mad; WF['z'] = Zw.abs().max(axis=1); WF['feature'] = Zw.abs().idxmax(axis=1); WF['dev'] = [('above' if Zw.loc[i, f] > 0 else 'below') for i, f in zip(WF.index, WF.feature)]
ANOM = [dict(entity=EN.loc[r.entity_id, 'name'], week=str(r.wk), indicator=r.feature, direction=r.dev + ' own norm', value=round(float(WF.loc[i, r.feature]), 2), z=round(float(r.z), 1)) for i, r in WF.sort_values('z', ascending=False).head(20).iterrows()]
TREND = {e: {c: [round(float(v), 3) for v in d[c]] for c in FE} | {'weeks': [str(w) for w in d.wk]} for e, d in WF.groupby('entity_id')}

Cx = C.merge(A[['alert_id', 'rep', 'rule_name']], left_on='source_alert_id', right_on='alert_id', how='left'); gm = C.dur.median(); Cx['outcome'] = Cx.outcome.fillna('')
Cx['iss'] = [[t for t, f in [('No evidence attached', r.evidence_attached == 'No'), ('Closure reason missing', r.status == 'Closed' and pd.isna(r.closure_reason)), ('Template/copy-paste notes', bool(r.tpl)),
    ('Investigation duration > 2x overall median', bool(pd.notna(r.dur) and r.dur > 2 * gm)), ('Case still open', r.status == 'Open'), ('Repeat pattern on same asset', bool(r.rep >= 6))] if f] for r in Cx.itertuples()]
Cx['cs'] = Cx.iss.str.len() * 10 + Cx.severity.map({'Low': 0, 'Medium': 5, 'High': 10, 'Critical': 15}) + Cx.entity_id.map(score) * .2
_t = lambda v: '-' if pd.isna(v) or v == '' else str(v)
CASES = [dict(case_id=r.case_id, entity=EN.loc[r.entity_id, 'name'], severity=r.severity, rule=r.rule_name, asset=r.asset_id, analyst=r.analyst_id, status=r.status, outcome=r.outcome or '-', notes_words=int(r.notes_word_count),
    duration_h=None if pd.isna(r.dur) else round(float(r.dur), 1), timeline=[('Detected', _t(r.detected_at)), ('Investigation started', _t(r.investigation_started_at)), ('Escalated', _t(r.escalated_at)), ('Closed', _t(r.closed_at))],
    issues=r.iss, priority=round(float(r.cs), 1)) for r in Cx.sort_values('cs', ascending=False).head(300).itertuples()]
data = dict(kpi=dict(entities=len(ents), alerts=len(A), cases=len(C), high=sum(x['level'] == 'HIGH' for x in ents)), entities=ents, queue=queue,
            audit=dict(generated=dt.datetime.now().isoformat(timespec='seconds'), weights=W, inputs={f: hashlib.sha256(open(f, 'rb').read()).hexdigest()[:16] for f in F}, method='Robust (median/MAD) peer z-scores, adverse direction, weighted sum'))
json.dump(data['audit'], open('audit_log.json', 'w'), indent=1)
data['cases'] = CASES; data['anomalies'] = ANOM; data['trend'] = TREND; data['peer'] = {k: round(float(med[k]), 3) for k in W}; json.dump(data, open('data.json', 'w'), default=str)

HTML = """<!doctype html><meta charset=utf-8><title>SAT-SA</title><style>
body{font:14px Arial;margin:0;background:#0f172a;color:#e2e8f0}header{background:#1e293b;padding:12px 20px;display:flex;gap:20px;align-items:center}
header b{font-size:18px}a.t{cursor:pointer;color:#94a3b8}a.t.on{color:#fff;border-bottom:2px solid #38bdf8}main{padding:20px}
.k{display:inline-block;background:#1e293b;padding:12px 20px;margin:0 10px 14px 0;border-radius:6px}.k b{font-size:22px;display:block}
table{width:100%;border-collapse:collapse;background:#1e293b}td,th{padding:7px 10px;text-align:left;border-bottom:1px solid #334155}tr.c{cursor:pointer}tr.c:hover{background:#334155}
.bar{display:inline-block;height:10px;background:#38bdf8;vertical-align:middle}.HIGH{color:#f87171}.MEDIUM{color:#fbbf24}.LOW{color:#4ade80}
.f{background:#1e293b;padding:12px;margin:10px 0;border-left:4px solid #38bdf8;border-radius:4px}small{color:#94a3b8}button{background:#334155;color:#e2e8f0;border:0;padding:4px 10px;cursor:pointer}
</style><header><b>SAT-SA</b><small>Supervisory Analytics Tool for SOC Assessment &middot; offline</small><a class="t on" onclick="go('d')">Dashboard</a><a class="t" onclick="go('q')">Priority Queue</a><a class="t" onclick="go('a')">Audit</a></header><main id=m></main>
<script>const D=__DATA__;const m=document.getElementById('m');let cur='d';
const go=v=>{cur=v;document.querySelectorAll('.t').forEach((t,i)=>t.classList.toggle('on','dqa'[i]==v));draw()};
const spark=w=>{const x=Math.max(...w);return `<svg width=200 height=40>${w.map((v,i)=>`<rect x=${i*15} y=${40-v/x*38} width=12 height=${v/x*38} fill="#38bdf8"/>`).join('')}</svg>`};
const tbl=(rows)=>!rows.length?'':`<table><tr>${Object.keys(rows[0]).map(k=>`<th>${k}</th>`).join('')}</tr>${rows.map(r=>`<tr>${Object.values(r).map(v=>`<td>${v}</td>`).join('')}</tr>`).join('')}</table>`;
function draw(){if(cur=='d')m.innerHTML=`${Object.entries({'Entities assessed':D.kpi.entities,'Alerts analysed':D.kpi.alerts.toLocaleString(),'Cases analysed':D.kpi.cases.toLocaleString(),'High-attention entities':D.kpi.high}).map(([a,b])=>`<div class=k><b>${b}</b>${a}</div>`).join('')}
<h3>Entity attention (peer-benchmarked)</h3><table><tr><th>Entity<th>Sector<th>Alerts<th>Cases<th>Score<th>Attention<th>Findings</tr>${D.entities.map(e=>`<tr class=c onclick="ent('${e.id}')"><td>${e.name}<td>${e.sector}<td>${e.alerts}<td>${e.cases}<td><span class=bar style="width:${e.score*2}px"></span> ${e.score}<td class=${e.level}>${e.level}<td>${e.findings.length}</tr>`).join('')}</table><small>Click an entity to drill down. Scores are this prototype's methodology, not an official NCIIPC score.</small>`;
else if(cur=='q')m.innerHTML='<h3>Alert samples prioritised for manual review</h3>'+tbl(D.queue);
else m.innerHTML='<h3>Audit trail</h3><pre>'+JSON.stringify(D.audit,null,1)+'</pre>'}
function ent(id){const e=D.entities.find(x=>x.id==id);m.innerHTML=`<a class=t onclick="go('d')">&larr; Back</a><h2>${e.name} <span class=${e.level}>${e.level}</span> <small>score ${e.score}</small></h2>Weekly alert volume ${spark(e.weekly)}
${e.findings.map(f=>`<div class=f><b>${f.type} &middot; ${f.capability}</b><br>${f.text}<br><small>Why it matters: ${f.why} (peer deviation z=${f.z})</small><br><button onclick="this.nextElementSibling.hidden=!this.nextElementSibling.hidden">Evidence</button><div hidden>${tbl(f.evidence)}</div></div>`).join('')||'No findings above threshold.'}`}
draw()</script>"""
open('dashboard.html', 'w').write(HTML.replace('__DATA__', json.dumps(data, default=str)))
print(pd.DataFrame({'score': score.round(1), 'level': score.map(lvl), 'blind': M.blind.round(2), 'fast': M.fast_close.round(2)}).sort_values('score', ascending=False).to_string())
