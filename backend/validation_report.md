# SAT-SA validation report
Benchmark source: synthetic ground truth (sanity check only)
- Spearman rank correlation (tool vs benchmark, entities): 0.87
- Precision@3 (top-3 entities overlap): 100%  (random sampling expectation: 25%)
- Priority-queue lift: 2.6x more alerts from benchmark-weak entities than a random alert sample (base rate 35%)
## Method for real validation
1. Examiners independently review a stratified sample per entity and record an examiner_score (0-1) plus flagged issues.
2. Save as examiner_labels.csv (name, examiner_score); re-run validate.py.
3. Report Spearman, precision@k, recall of examiner-confirmed findings in the top-N queue, and effort saved (samples reviewed to reach the same findings).
## Limitations
Synthetic data was generated with the same signal families the detectors use, and thresholds were tuned on it; results are optimistic.
