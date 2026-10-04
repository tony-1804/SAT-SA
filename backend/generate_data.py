"""
SAT-SA synthetic SOC dataset generator.
All data is fictional. Entities are anonymised (Entity A..L).
Each entity gets a hidden "weakness profile" so the analytics engine has real
signal to find; the profiles are exported to ground_truth_profiles.csv for
validating your scoring model (do NOT show this file to the "examiner" UI).

Run:  python generate_data.py
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

rng = np.random.default_rng(26157)
START = datetime(2026, 6, 1)
DAYS = 90

# ---------------------------------------------------------------- entities
# weakness knobs (0 = healthy, 1 = severe)
# delay: slow closure | doc: missing evidence/closure reason | repeat: same
# rule/asset recurring | stale: alerts left open | inconsistent: same rule,
# different outcomes | sev_bias: real severity under-rated at triage
ENT = [
    # id, name, sector, soc_model, n_alerts, delay, doc, repeat, stale, inconsistent, sev_bias
    ("E01", "Entity A", "Power",      "In-house",   1400, 0.90, 0.80, 0.85, 0.80, 0.85, 0.70),
    ("E02", "Entity B", "Banking",    "Outsourced", 1500, 0.75, 0.70, 0.60, 0.65, 0.80, 0.55),
    ("E03", "Entity C", "Telecom",    "Outsourced", 1300, 0.70, 0.85, 0.70, 0.55, 0.50, 0.60),
    ("E04", "Entity D", "Oil & Gas",  "In-house",    900, 0.50, 0.45, 0.50, 0.40, 0.40, 0.30),
    ("E05", "Entity E", "Transport",  "Hybrid",      800, 0.45, 0.50, 0.35, 0.45, 0.30, 0.35),
    ("E06", "Entity F", "Health",     "Outsourced",  700, 0.40, 0.35, 0.45, 0.30, 0.40, 0.25),
    ("E07", "Entity G", "Banking",    "In-house",   1000, 0.35, 0.30, 0.30, 0.25, 0.25, 0.20),
    ("E08", "Entity H", "Power",      "Hybrid",      600, 0.20, 0.20, 0.20, 0.15, 0.15, 0.10),
    ("E09", "Entity I", "Telecom",    "In-house",    900, 0.15, 0.15, 0.15, 0.10, 0.10, 0.10),
    ("E10", "Entity J", "Insurance",  "Outsourced",  500, 0.20, 0.10, 0.20, 0.15, 0.20, 0.10),
    ("E11", "Entity K", "Government", "In-house",    700, 0.10, 0.10, 0.10, 0.05, 0.10, 0.05),
    ("E12", "Entity L", "Banking",    "In-house",    600, 0.05, 0.05, 0.10, 0.05, 0.05, 0.05),
]
ent_cols = ["entity_id", "name", "sector", "soc_model", "n_alerts",
            "delay", "doc", "repeat_", "stale", "inconsistent", "sev_bias"]
ent_df = pd.DataFrame(ENT, columns=ent_cols)

# ------------------------------------------------------------- rule catalog
RULES = [
    # rule_id, name, category, base_severity, base_fp_rate
    ("R101", "Multiple failed logins",           "Authentication",    "Low",      0.75),
    ("R102", "Login from unusual geography",      "Authentication",    "Medium",   0.55),
    ("R103", "Privileged account added",          "Privilege Abuse",   "High",     0.20),
    ("R104", "Outbound traffic to rare domain",   "Exfiltration",      "Medium",   0.50),
    ("R105", "Large data transfer off-hours",     "Exfiltration",      "High",     0.30),
    ("R106", "Malware signature on endpoint",     "Malware",           "High",     0.25),
    ("R107", "Suspicious PowerShell execution",   "Malware",           "Medium",   0.45),
    ("R108", "Port scan from internal host",      "Reconnaissance",    "Low",      0.65),
    ("R109", "Unpatched service exploited",       "Vulnerability",     "Critical", 0.10),
    ("R110", "Phishing email reported",           "Phishing",          "Medium",   0.40),
    ("R111", "Firewall rule modified",            "Config Change",     "Medium",   0.50),
    ("R112", "ICS/SCADA protocol anomaly",        "OT Anomaly",        "High",     0.35),
    ("R113", "DNS tunnelling pattern",            "Exfiltration",      "High",     0.25),
    ("R114", "Ransomware behaviour (file burst)", "Malware",           "Critical", 0.10),
    ("R115", "Service account interactive login", "Privilege Abuse",   "Medium",   0.40),
]
rule_df = pd.DataFrame(RULES, columns=["rule_id", "rule_name", "category",
                                       "base_severity", "base_fp_rate"])
SEV = ["Low", "Medium", "High", "Critical"]
SEV_RANK = {s: i for i, s in enumerate(SEV)}
TOOLS = ["SIEM", "EDR", "NDR", "Email Gateway", "Firewall", "OT Sensor"]
ANALYSTS_PER_ENTITY = 6


def rand_ts(n):
    """Timestamps with business-hours skew."""
    day = rng.integers(0, DAYS, n)
    hour = np.where(rng.random(n) < 0.7, rng.integers(8, 20, n), rng.integers(0, 24, n))
    minute = rng.integers(0, 60, n)
    return [START + timedelta(days=int(d), hours=int(h), minutes=int(m))
            for d, h, m in zip(day, hour, minute)]


alerts, cases = [], []
case_counter = 1
alert_counter = 1

for _, e in ent_df.iterrows():
    n = int(e.n_alerts)
    eid = e.entity_id
    assets = [f"{eid}-AST-{i:03d}" for i in range(1, 60)]
    analysts = [f"{eid}-AN{i}" for i in range(1, ANALYSTS_PER_ENTITY + 1)]

    # a few "hot" (rule, asset) pairs that recur more in weak entities
    hot_pairs = [(RULES[rng.integers(0, len(RULES))][0], assets[rng.integers(0, 10)])
                 for _ in range(4)]

    ts = rand_ts(n)
    for i in range(n):
        if rng.random() < e.repeat_ * 0.35:                # repeated pattern
            rid, asset = hot_pairs[rng.integers(0, len(hot_pairs))]
        else:
            rid = RULES[rng.integers(0, len(RULES))][0]
            asset = assets[rng.integers(0, len(assets))]
        r = rule_df[rule_df.rule_id == rid].iloc[0]

        # severity as assigned at triage; weak SOCs under-rate
        sev_idx = SEV_RANK[r.base_severity]
        if rng.random() < e.sev_bias * 0.45 and sev_idx > 0:
            sev_idx -= 1
        severity = SEV[sev_idx]

        is_fp = rng.random() < r.base_fp_rate
        # inconsistent handling: same rule ends with a random outcome
        if rng.random() < e.inconsistent * 0.30:
            is_fp = rng.random() < 0.5

        stale = rng.random() < e.stale * 0.12
        t0 = ts[i]
        base_h = {"Low": 24, "Medium": 12, "High": 6, "Critical": 2}[severity]
        close_h = rng.lognormal(mean=np.log(base_h * (1 + 4 * e.delay)), sigma=0.6)
        closed_at = None if stale else t0 + timedelta(hours=float(close_h))

        if stale:
            status = "Open"
        elif is_fp:
            status = "Closed - False Positive"
        else:
            status = "Escalated to Case"

        # closure reason completeness
        reason = None
        if status.startswith("Closed"):
            reason = "" if rng.random() < e.doc * 0.35 else "No malicious activity confirmed"

        alerts.append(dict(
            alert_id=f"ALT-{alert_counter:06d}", entity_id=eid,
            timestamp=t0.isoformat(sep=" "), source_tool=TOOLS[rng.integers(0, len(TOOLS))],
            rule_id=rid, rule_name=r.rule_name, category=r.category,
            severity=severity, asset_id=asset, analyst_id=analysts[rng.integers(0, len(analysts))],
            status=status,
            closed_at=closed_at.isoformat(sep=" ") if closed_at else "",
            closure_reason=reason if reason is not None else "",
            case_id="",
        ))
        alert_counter += 1

    # ---- build cases from escalated alerts
    ent_alerts = [a for a in alerts if a["entity_id"] == eid and a["status"] == "Escalated to Case"]
    for a in ent_alerts:
        cid = f"CASE-{case_counter:05d}"
        case_counter += 1
        a["case_id"] = cid
        det = datetime.fromisoformat(a["timestamp"])
        inv_start = det + timedelta(hours=float(rng.lognormal(np.log(2 * (1 + 3 * e.delay)), 0.5)))
        dur_h = rng.lognormal(np.log(24 * (1 + 4 * e.delay)), 0.6)
        esc = inv_start + timedelta(hours=float(dur_h * rng.uniform(0.3, 0.7)))
        still_open = rng.random() < e.stale * 0.10
        closed = None if still_open else inv_start + timedelta(hours=float(dur_h))
        missing_evidence = rng.random() < e.doc * 0.40
        weak_reason = rng.random() < e.doc * 0.45
        outcome = rng.choice(["True Positive - Contained", "True Positive - Not Contained",
                              "Benign True Positive", "Inconclusive"],
                             p=[0.45, 0.10, 0.30, 0.15] if e.inconsistent < 0.5
                             else [0.25, 0.10, 0.25, 0.40])
        cases.append(dict(
            case_id=cid, entity_id=eid, source_alert_id=a["alert_id"],
            rule_id=a["rule_id"], category=a["category"], asset_id=a["asset_id"],
            severity=a["severity"], analyst_id=a["analyst_id"],
            detected_at=det.isoformat(sep=" "),
            investigation_started_at=inv_start.isoformat(sep=" "),
            escalated_at=esc.isoformat(sep=" "),
            closed_at=closed.isoformat(sep=" ") if closed else "",
            status="Open" if still_open else "Closed",
            evidence_attached="No" if missing_evidence else "Yes",
            closure_reason="" if (still_open or weak_reason) else "Investigation complete; remediation confirmed",
            outcome="" if still_open else outcome,
            notes_word_count=int(rng.integers(0, 15) if weak_reason else rng.integers(30, 220)),
        ))

alerts_df = pd.DataFrame(alerts)
cases_df = pd.DataFrame(cases)

# ---- asset inventory + negative space + execution-gap plants
asset_rows = []
flipped = []
for _, e in ent_df.iterrows():
    ids = [f"{e.entity_id}-AST-{i:03d}" for i in range(1, 60)]
    crit = ids[::6]
    asset_rows += [dict(asset_id=a, entity_id=e.entity_id,
                        criticality="Critical" if a in crit else "Standard") for a in ids]
    blind = crit[:int(round(e.stale * 6))]              # critical assets with no telemetry
    alerts_df.loc[alerts_df.asset_id.isin(blind), "asset_id"] = ids[1]
    cases_df.loc[cases_df.asset_id.isin(blind), "asset_id"] = ids[1]
    m = (alerts_df.entity_id == e.entity_id) & alerts_df.severity.isin(["High", "Critical"])
    fp = alerts_df[m & (alerts_df.status == "Closed - False Positive")]
    q = fp.sample(frac=min(1, 0.7 * e.delay), random_state=1).index   # closed within minutes
    alerts_df.loc[q, "closed_at"] = [(datetime.fromisoformat(t) + timedelta(minutes=int(rng.integers(1, 10)))).isoformat(sep=" ")
                                     for t in alerts_df.loc[q, "timestamp"]]
    esc = alerts_df[m & (alerts_df.status == "Escalated to Case")]
    f = esc.sample(frac=0.30 * e.doc, random_state=2).index         # high/critical closed, never escalated
    alerts_df.loc[f, ["status", "closure_reason"]] = ["Closed - False Positive", ""]
    alerts_df.loc[f, "closed_at"] = alerts_df.loc[f, "timestamp"]
    flipped += list(alerts_df.loc[f, "alert_id"])
    alerts_df.loc[f, "case_id"] = ""
cases_df = cases_df[~cases_df.source_alert_id.isin(flipped)].copy()
# ---- negative space plants: absent alert categories + silent period
_d = (pd.to_datetime(alerts_df.timestamp, format="mixed") - START).dt.days
_gone = (((alerts_df.entity_id == "E01") & (alerts_df.category == "Exfiltration")) |
         ((alerts_df.entity_id == "E03") & (alerts_df.category == "OT Anomaly")) |
         ((alerts_df.entity_id == "E04") & (alerts_df.category == "Phishing")) |
         ((alerts_df.entity_id == "E02") & _d.between(56, 77) & (rng.random(len(alerts_df)) < 0.75)))
_ids = set(alerts_df[_gone].alert_id)
alerts_df = alerts_df[~_gone].copy()
cases_df = cases_df[~cases_df.source_alert_id.isin(_ids)].copy()
_dc = cases_df.entity_id.map(ent_df.set_index('entity_id').doc)
cases_df = cases_df[~(rng.random(len(cases_df)) < _dc * 0.6)].copy()   # escalated alerts with no case record
dm = cases_df.entity_id.map(ent_df.set_index("entity_id").doc)
tpl = rng.random(len(cases_df)) < dm * 0.6                          # copy-paste investigation notes
cases_df["note_hash"] = [f"TPL{rng.integers(1, 4)}" if t else f"N{i}" for i, t in enumerate(tpl)]
pd.DataFrame(asset_rows).to_csv("assets.csv", index=False)

# ------------------------------------------------------------------ export
alerts_df.to_csv("alerts.csv", index=False)
cases_df.to_csv("cases.csv", index=False)
ent_df[["entity_id", "name", "sector", "soc_model"]].to_csv("entities.csv", index=False)
rule_df.to_csv("rule_catalog.csv", index=False)
ent_df[["entity_id", "name", "delay", "doc", "repeat_", "stale", "inconsistent", "sev_bias"]] \
    .to_csv("ground_truth_profiles.csv", index=False)

print(f"entities: {len(ent_df)}  alerts: {len(alerts_df):,}  cases: {len(cases_df):,}")
print(alerts_df.status.value_counts().to_string())
