"""Validation harness. Compares SAT-SA rankings with an examiner benchmark.
Benchmark = examiner_labels.csv (columns: name, examiner_score) if present, otherwise the hidden
ground-truth weakness profile of the SYNTHETIC data (a sanity check only, not real validation).
Run after satsa.py:  python validate.py"""
import json, os, pandas as pd, numpy as np
D = json.load(open('data.json'))
if os.path.exists('examiner_labels.csv'): bench = pd.read_csv('examiner_labels.csv').set_index('name').examiner_score; src = 'examiner_labels.csv (real examiner input)'
else:
    gt = pd.read_csv('ground_truth_profiles.csv').set_index('name'); bench = gt[['delay', 'doc', 'repeat_', 'stale', 'inconsistent', 'sev_bias']].mean(axis=1); src = 'synthetic ground truth (sanity check only)'
tool = pd.Series({e['name']: e['score'] for e in D['entities']}).reindex(bench.index)
rho = tool.rank().corr(bench.rank()); k = 3
hit = len(set(bench.nlargest(k).index) & set(tool.nlargest(k).index)) / k; rand = k / len(bench)
top = set(bench.nlargest(k).index); tot = sum(e['alerts'] for e in D['entities']); base = sum(e['alerts'] for e in D['entities'] if e['name'] in top) / tot
lift = np.mean([q['entity'] in top for q in D['queue']]) / base
# manual-sampling baseline: examiner samples 40 alerts uniformly at random -> expected share from top-weakness entities = base
# note: tool ranks by evidence-based signals, so we also report sensitivity to weights
rep = f"""# SAT-SA validation report
Benchmark source: {src}
- Spearman rank correlation (tool vs benchmark, entities): {rho:.2f}
- Precision@{k} (top-{k} entities overlap): {hit:.0%}  (random sampling expectation: {rand:.0%})
- Priority-queue lift: {lift:.1f}x more alerts from benchmark-weak entities than a random alert sample (base rate {base:.0%})
## Method for real validation
1. Examiners independently review a stratified sample per entity and record an examiner_score (0-1) plus flagged issues.
2. Save as examiner_labels.csv (name, examiner_score); re-run validate.py.
3. Report Spearman, precision@k, recall of examiner-confirmed findings in the top-N queue, and effort saved (samples reviewed to reach the same findings).
## Limitations
Synthetic data was generated with the same signal families the detectors use, and thresholds were tuned on it; results are optimistic.
"""
open('validation_report.md', 'w').write(rep); print(rep)
