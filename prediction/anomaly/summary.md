# Anomaly Experiment Summary

## Best models

- Early warning (`merged_5.csv`): `LOF`
  - Test recall: `0.9998`
  - Test precision: `0.9996`
  - Test F1: `0.9997`
  - Test normal FPR: `0.0525`

- Final confirmation (`merged_full.csv`): `LOF`
  - Test recall: `0.9045`
  - Test precision: `0.9996`
  - Test F1: `0.9497`
  - Test normal FPR: `0.0478`

## Two-stage policy

- `early_warning`
  - Precision: `0.9996`
  - Recall: `0.9998`
  - F1: `0.9997`
  - Normal FPR: `0.0525`
- `final_confirmation`
  - Precision: `0.9996`
  - Recall: `0.9045`
  - F1: `0.9497`
  - Normal FPR: `0.0463`
- `any_stage`
  - Precision: `0.9993`
  - Recall: `1.0000`
  - F1: `0.9996`
  - Normal FPR: `0.0910`
