# 이상 탐지 결과 종합 분석

## 개요

이 문서는 `prediction/anomaly_benchmark`에 저장된 tabular anomaly benchmark 결과를 종합 해석한 문서다.

대상 모델:

- `IsolationForest`
- `HBOS`
- `ECOD`
- `PCAReconstruction`
- `Autoencoder`

대상 데이터:

- `merged/merged_5.csv`
- `merged/merged_full.csv`

관련 비교 문서:

- [표 형식 이상 탐지 벤치마크 비교](./anomaly-benchmark-comparison.md)

## 실험 설정 요약

- 학습 데이터는 `NORMAL`만 사용했다.
- 검증/테스트 데이터는 `NORMAL + ABNORMAL`로 구성했다.
- 분할 단위는 row가 아니라 `source_file`이다.
- 초기 단계는 `merged_5.csv`, 최종 단계는 `merged_full.csv`를 사용했다.
- threshold는 validation에서 선택했다.
  - 초기 단계: `normal FPR <= 10%` 조건에서 이상 재현율 최대화
  - 최종 단계: `normal FPR <= 5%` 조건에서 F1 최대화

### source_file 분할 수

| label | train | valid | test |
| --- | ---: | ---: | ---: |
| NORMAL | 24 | 5 | 5 |
| GET_FLOOD | 0 | 35 | 36 |
| CONNECTION_FLOOD | 0 | 8 | 9 |
| SCAN | 0 | 7 | 7 |

### test row 수

#### `merged_5.csv`

| label | rows |
| --- | ---: |
| NORMAL | 648 |
| GET_FLOOD | 1390 |
| CONNECTION_FLOOD | 71528 |
| SCAN | 12995 |

#### `merged_full.csv`

| label | rows |
| --- | ---: |
| NORMAL | 649 |
| GET_FLOOD | 1390 |
| CONNECTION_FLOOD | 71528 |
| SCAN | 12996 |

이 분포는 매우 불균형하다. 특히 `CONNECTION_FLOOD` 비중이 압도적으로 크기 때문에, 단일 aggregate metric만 보면 일부 모델이 실제보다 좋아 보일 수 있다. 따라서 이번 결과 해석에서는 다음 순서를 더 중요하게 봐야 한다.

1. 공격 유형별 재현율
2. 정상 FPR
3. F1
4. ROC-AUC / PR-AUC

## 핵심 결론

### 1. 전체적으로는 `Autoencoder`가 가장 강했다

- 초기 단계: `precision 0.9991 / recall 1.0000 / F1 0.9995 / normal FPR 0.1204`
- 최종 단계: `precision 0.9992 / recall 0.9908 / F1 0.9950 / normal FPR 0.1002`

특히 공격별 재현율도 가장 안정적이었다.

- 초기 단계에서 `GET_FLOOD`, `CONNECTION_FLOOD`, `SCAN` 모두 `1.0000`
- 최종 단계에서도 `GET_FLOOD 1.0000`, `CONNECTION_FLOOD 0.999958`, `SCAN 0.939135`

즉 현재 데이터 기준에서는 `Autoencoder`가 가장 유력한 주력 모델이다.

### 2. 고전 모델 중에서는 역할이 갈렸다

- `HBOS`: 초기 단계에서는 강하지만 오탐이 높고 full 단계에서 불안정
- `ECOD`: 초기 단계는 약하지만 full 단계에서는 꽤 강함
- `PCAReconstruction`: 초기 단계는 부적합하지만 full 단계 baseline으로는 경쟁력 있음
- `IsolationForest`: 이번 데이터에서는 가장 약한 편

### 3. “5패킷 early detector + full confirmer” 구조는 모델에 따라 효과가 다르다

- `Autoencoder`는 초기 단계 성능이 이미 너무 높아서 OR 결합 이득이 거의 없고, 오히려 정상 FPR만 증가한다.
- `PCAReconstruction`은 early와 full이 서로 다른 공격을 잡아주기 때문에 OR 결합 효과가 크다.
- `HBOS`는 OR 결합 시 recall은 좋아지지만 정상 FPR이 너무 높아진다.

즉 2단계 구조 자체가 항상 좋은 것은 아니고, 각 stage가 서로 보완 관계인지 먼저 확인해야 한다.

## 모델별 분석

### Autoencoder

장점:

- 초기 단계와 최종 단계 모두 최고 성능
- 공격 유형별 재현율 편차가 가장 작음
- `5패킷`만으로도 거의 ceiling 성능에 가까움

약점:

- 정상 FPR이 `0.10~0.12` 수준이라 운영 기준으로는 아직 높다
- 성능이 너무 강하게 나오므로 과적합 또는 데이터 분할 특이성 여부를 더 검증해야 한다

해석:

- 현재 데이터 구조에서는 가장 유망한 후보
- 다만 “배포 후보”로 보기 전에 더 강한 일반화 검증이 필요하다

### HBOS

장점:

- 초기 단계 baseline으로는 꽤 강함
- 구현이 단순하고 계산도 가벼움

약점:

- 정상 FPR이 매우 높다
- full 단계에서 `SCAN` 재현율이 `0.0887`까지 무너진다

해석:

- “가벼운 고전 baseline”으로는 가치가 있다
- 하지만 운영용 주력 모델로 쓰기에는 안정성이 부족하다

### ECOD

장점:

- full 단계에서 `F1 0.9647`, `recall 0.9335`
- `CONNECTION_FLOOD` 탐지는 매우 강함

약점:

- 초기 단계에서는 `GET_FLOOD`와 `SCAN`을 거의 잡지 못한다
- 정상 FPR도 낮지 않다

해석:

- 조기 탐지기보다는 full flow 기반 최종 확인 모델에 더 가까운 성격
- 고전 모델 중에서는 final-stage baseline으로 가장 설득력 있다

### PCAReconstruction

장점:

- full 단계에서 `F1 0.9373`, `normal FPR 0.1109`
- `GET_FLOOD`, `CONNECTION_FLOOD`에는 꽤 강함
- 해석이 비교적 쉬워 논문용 baseline으로 좋음

약점:

- 초기 단계 성능이 매우 약하다
- 공격별 편차가 심하다
  - 초기 단계에서는 `CONNECTION_FLOOD`를 거의 못 잡음
  - full 단계에서는 `SCAN`이 약함

해석:

- 초기 경보 모델로는 부적합
- full-stage reconstruction baseline으로는 충분히 가치가 있다

### IsolationForest

장점:

- 가장 널리 알려진 one-class baseline 중 하나
- 구현과 설명이 쉬움

약점:

- 이번 benchmark에서는 가장 약했다
- `GET_FLOOD`와 `SCAN` 재현율이 매우 낮다
- 정상 FPR도 높다

해석:

- 참조 baseline으로는 남길 수 있다
- 실전 후보로는 우선순위가 낮다

## 단계별 분석

### 초기 단계 (`merged_5.csv`)

초기 단계에서 중요한 것은 false negative를 줄이는 것이다. 이 기준으로 보면 순위는 거의 명확하다.

1. `Autoencoder`
2. `HBOS`
3. `IsolationForest`
4. `ECOD`
5. `PCAReconstruction`

다만 단순 recall만 보면 안 된다.

- `Autoencoder`는 재현율이 `1.0000`이지만 정상 FPR도 `0.1204`
- `HBOS`는 재현율 `0.9528`이지만 정상 FPR이 `0.2793`
- `PCAReconstruction`은 정상 FPR은 낮은 편이지만 `CONNECTION_FLOOD`를 거의 놓친다

결론적으로 초기 단계에서는 `Autoencoder` 외에는 뚜렷하게 균형 잡힌 대안이 없다.

### 최종 단계 (`merged_full.csv`)

최종 단계는 precision/F1 중심으로 보는 게 맞다.

1. `Autoencoder`
2. `ECOD`
3. `PCAReconstruction`
4. `HBOS`
5. `IsolationForest`

여기서 눈여겨볼 점은 다음이다.

- `ECOD`는 초기 단계에서 약했지만 full 단계에서 크게 좋아진다
- `PCAReconstruction`은 정상 FPR이 비교적 낮고, `GET_FLOOD`와 `CONNECTION_FLOOD`에 강하다
- `HBOS`는 full 단계로 가도 안정성이 크게 개선되지 않는다

즉 full 단계의 고전 baseline은 `ECOD`와 `PCAReconstruction`이 더 의미 있다.

## 공격 유형별 분석

### GET_FLOOD

- 가장 잘 잡은 모델: `Autoencoder`
- `PCAReconstruction`도 잘 잡음
- `IsolationForest`, `ECOD`는 초기 단계에서 매우 약함
- `HBOS`는 초기 단계에서는 중간 이상이지만 full 단계에서 오히려 약해짐

해석:

- `GET_FLOOD`는 reconstruction 기반 모델에 잘 맞고, density/tail 기반 모델은 stage에 따라 편차가 큼

### CONNECTION_FLOOD

- 대부분 모델이 full 단계에서는 강하다
- `PCAReconstruction`만 초기 단계에서 크게 약하다

해석:

- 이 공격은 flow가 길어질수록 구조적 패턴이 더 잘 드러나는 것으로 보인다
- aggregate metric이 높게 보이는 이유 중 하나도 `CONNECTION_FLOOD` row 비중이 매우 크기 때문이다

### SCAN

- `Autoencoder`는 안정적으로 강하다
- `HBOS`와 `PCAReconstruction`은 초기 단계에서 강하지만 full 단계에서 약해질 수 있다
- `IsolationForest`는 거의 못 잡는다

해석:

- `SCAN`은 모델에 따라 early/local density 신호로는 잘 잡히지만, full 단계에서 분포가 normal과 더 섞이는 것으로 보인다
- 이 때문에 full-stage 성능만 보고 모델을 고르면 `SCAN` 대응력이 떨어질 수 있다

## 2단계 정책 분석

### Autoencoder

| 정책 | Precision | Recall | F1 | Normal FPR |
| --- | ---: | ---: | ---: | ---: |
| early_warning | 0.999093 | 1.000000 | 0.999546 | 0.120370 |
| final_confirmation | 0.999249 | 0.990758 | 0.994985 | 0.098765 |
| any_stage | 0.998547 | 1.000000 | 0.999273 | 0.192901 |

해석:

- `early_warning`만으로도 거의 충분하다
- OR 결합은 성능 이득이 거의 없고 정상 오탐만 늘린다

### PCAReconstruction

| 정책 | Precision | Recall | F1 | Normal FPR |
| --- | ---: | ---: | ---: | ---: |
| early_warning | 0.995994 | 0.225717 | 0.368029 | 0.120370 |
| final_confirmation | 0.999065 | 0.882777 | 0.937328 | 0.109568 |
| any_stage | 0.998589 | 0.988279 | 0.993407 | 0.185185 |

해석:

- 이 모델은 early와 full이 서로 다른 공격을 잡기 때문에 OR 결합 효과가 매우 크다
- 다만 정상 FPR 상승도 함께 감수해야 한다

### HBOS / ECOD / IsolationForest

- `HBOS`: OR 결합 시 recall은 좋아지지만 FPR이 `0.3395`
- `ECOD`: OR 결합 이득은 제한적이고 FPR 상승이 존재
- `IsolationForest`: OR 결합을 해도 경쟁력이 충분하지 않다

결론:

- 2단계 구조는 “항상 이득”이 아니라 “stage 간 보완성”이 있을 때만 의미가 있다

## 중요한 해석 포인트

### 1. PR-AUC만 보면 안 된다

대부분 모델의 PR-AUC가 높다. 하지만 이 결과만 보고 모델이 좋다고 판단하면 위험하다.

이유:

- `CONNECTION_FLOOD` row 비중이 너무 크다
- 이 공격만 잘 잡아도 aggregate metric이 높게 나온다
- 반대로 `GET_FLOOD`나 `SCAN`을 놓쳐도 PR-AUC가 크게 나쁘지 않을 수 있다

즉 이 문제에서는 PR-AUC보다 공격별 재현율과 정상 FPR이 더 중요하다.

### 2. validation threshold가 test에서 그대로 유지되지 않는다

설계상 validation에서는 정상 FPR 제약을 두고 threshold를 골랐다. 그런데 test에서 많은 모델이 그 목표를 상당히 초과했다.

예시:

- `HBOS` full: test 정상 FPR `0.2604`
- `ECOD` full: test 정상 FPR `0.2404`
- `IsolationForest` full: test 정상 FPR `0.2373`
- `Autoencoder` full도 `0.1002`

이건 threshold calibration이 아직 안정적이지 않다는 뜻이다.

가능한 원인:

- 정상 source file 수가 적다
- validation normal의 분포가 test normal과 다르다
- 모델 score 분포가 capture별로 흔들린다

따라서 다음 단계에서는 score calibration과 더 강한 홀드아웃 검증이 필요하다.

## 최종 추천

### 운영 후보

- 1순위: `Autoencoder`

이유:

- 초기 단계와 최종 단계 모두 가장 강함
- 공격별 재현율도 가장 고르게 높음
- 현재 데이터 기준으로는 다른 후보와 격차가 큼

단, 바로 운영에 넣기보다 아래를 먼저 해야 한다.

- threshold 재조정
- unseen capture/session 검증
- normal FPR 안정화 확인

### 논문용 고전 baseline

- `HBOS`
- `ECOD`
- `PCAReconstruction`
- `IsolationForest`는 참조 baseline으로 유지

추천 이유:

- `HBOS`: 가벼운 early baseline
- `ECOD`: 강한 full-stage classical baseline
- `PCAReconstruction`: 해석 가능한 reconstruction baseline
- `IsolationForest`: 가장 익숙한 one-class 기준선

## 다음 실험 제안

1. `Autoencoder`의 threshold sweep을 더 세밀하게 수행해서 정상 FPR을 낮춘다.
2. normal 파일을 더 확보하거나, validation/test normal의 capture 다양성을 늘린다.
3. `source_file`보다 더 강한 홀드아웃 기준을 적용한다.
4. 이후에는 sequence 기반 모델로 확장해 `packet size / direction / IAT` 시퀀스를 직접 사용해본다.

## 참고 산출물

- [표 형식 이상 탐지 벤치마크 비교](./anomaly-benchmark-comparison.md)
- [Autoencoder 결과](./anomaly-autoencoder.md)
- [HBOS 결과](./anomaly-hbos.md)
- [ECOD 결과](./anomaly-ecod.md)
- [IsolationForest 결과](./anomaly-isolation-forest.md)
- [PCAReconstruction 결과](./anomaly-pca-reconstruction.md)

## 비교 시각화

![단계별 재현율](../prediction/anomaly_benchmark/comparison/recall_by_stage.png)

![단계별 F1](../prediction/anomaly_benchmark/comparison/f1_by_stage.png)

![단계별 정상 FPR](../prediction/anomaly_benchmark/comparison/normal_fpr_by_stage.png)

![정책별 F1](../prediction/anomaly_benchmark/comparison/policy_f1.png)
