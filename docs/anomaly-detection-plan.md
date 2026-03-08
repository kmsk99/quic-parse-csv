# 이상 탐지 설계안

## 목적

기존 4-class 분류 파이프라인과 별도로, `NORMAL` 트래픽만 학습해서 비정상 트래픽을 걸러내는 이상 탐지 파이프라인을 설계한다.

최종 기준 데이터는 다음 두 개의 merged CSV로 둔다.

- `merged/merged_5.csv`
- `merged/merged_full.csv`

의도는 다음과 같다.

- `merged_5.csv`: 초반 5패킷만으로 빠르게 의심 흐름을 잡는 초기 경보 모델
- `merged_full.csv`: 전체 flow 기준으로 최종 판정 성능을 높이는 최종 확인 모델

## 방금 수행한 빠른 베이스라인 실험

빠른 확인을 위해 per-window CSV를 직접 읽어 anomaly score를 계산했다. 최종 구현은 `merged` 기준으로 바꾸되, 실험에서 본 경향은 설계 방향을 정하는 데 충분했다.

### 사용한 모델

이번에 돌린 것은 일반적인 다중 클래스 분류기가 아니라, 정상만 학습하는 이상 탐지 모델들이다.

- `LocalOutlierFactor(n_neighbors=35, novelty=True)`
- `IsolationForest(n_estimators=200, contamination="auto")`
- `OneClassSVM(kernel="rbf", nu=0.05, gamma="scale")`

### 공통 평가 방식

- 학습 데이터: `NORMAL`만 사용
- 평가 데이터: `NORMAL + 공격 트래픽`
- 점수 기준: 모델의 anomaly score 사용
- threshold: 학습 normal score의 상위 95 percentile
- 운영 해석:
  - threshold 초과 = 이상
  - threshold 이하 = 정상

## 빠른 실험 결과 요약

### 윈도우별 경향

- `5` 패킷 윈도우에서는 `LOF`가 가장 강했다.
- `25` 패킷 윈도우는 전체적으로 애매했고, 특히 `SCAN` 탐지가 약해졌다.
- `full` 윈도우는 전체 성능은 좋았지만, 일부 공격 타입에서는 `5`보다 조기 탐지성이 떨어질 수 있다.

### 파일 단위 홀드아웃 기준 주요 수치

#### `5` 패킷, `LOF`

- ROC-AUC: `0.9817`
- PR-AUC: `0.9996`
- F1 at 95p threshold: `0.9995`
- Normal false positive rate: 약 `7.3%`
- 공격 탐지율:
  - `GET_FLOOD`: `98.88%`
  - `CONNECTION_FLOOD`: `99.96%`
  - `SCAN`: `99.98%`

#### `5 + full` 점수 결합

`LOF(5)`와 `IsolationForest(full)`의 z-score를 정규화한 뒤 `max(z5, zfull)`로 결합했다.

- ROC-AUC: `0.9846`
- PR-AUC: `0.9997`
- F1 at 95p threshold: `0.9979`
- Normal false positive rate: 약 `4.2%`
- 공격 탐지율:
  - `GET_FLOOD`: `90.64%`
  - `CONNECTION_FLOOD`: `99.94%`
  - `SCAN`: `98.73%`

### 해석

- `5` 단독 모델은 조기 탐지 목적에 매우 잘 맞는다.
- `5 + full` 결합은 정상 오탐을 줄이는 데 유리하다.
- 다만 결합 방식에 따라 `GET_FLOOD` recall이 조금 줄 수 있으므로, 초기 단계와 최종 단계의 threshold를 분리해서 운영하는 편이 더 낫다.

## 권장 구조

2단계 이상 탐지 구조를 권장한다.

### 1단계: 초기 경보

대상:

- `merged/merged_5.csv`

목표:

- false negative를 줄여서 초반 공격 흐름을 빨리 잡기

설정 방향:

- `NORMAL`만 학습
- threshold는 다소 느슨하게 설정
- normal FPR을 조금 허용하더라도 이상 재현율을 우선

추천 시작점:

- `LOF`

출력:

- `early_score`
- `early_is_suspect`

### 2단계: 최종 확인

대상:

- `merged/merged_full.csv`

목표:

- 전체 flow 기준 최종 판정의 precision, F1, 해석 가능성을 높이기

설정 방향:

- `NORMAL`만 학습
- threshold는 더 타이트하게 설정
- normal FPR을 낮추는 방향으로 튜닝

추천 시작점:

- `IsolationForest`

출력:

- `final_score`
- `final_is_anomaly`

## 의사결정 로직

운영 로직은 다음처럼 단순하게 시작하는 것이 좋다.

1. flow가 5패킷에 도달하면 `early_score`를 계산한다.
2. `early_score`가 threshold를 넘으면 `suspect` 상태로 표시한다.
3. flow가 종료되거나 full feature가 준비되면 `final_score`를 계산한다.
4. 최종 상태는 `final_score`로 확정한다.

필요하면 최종 binary score를 아래처럼 결합할 수 있다.

- `combined_score = max(zscore(early_score), zscore(final_score))`

하지만 초기 구현에서는 다음처럼 분리 운영하는 편이 더 안전하다.

- 초기 단계는 recall 우선
- 최종 단계는 precision/F1 우선

## 특징 관점에서 보인 강한 신호

초기 5패킷 기준으로 normal과 abnormal을 잘 가른 feature는 대략 다음과 같았다.

- `entropy_packet_size`
- `initial_ratio`
- `initial_packets`
- `packet_size_cv`
- `incoming_packets`
- `outgoing_packets`
- `outgoing_bytes`
- `packet_size_std`
- `packet_size_var`
- `entropy_direction`

즉, 초반 패킷의 방향성, 초기 핸드셰이크 비율, 패킷 길이 다양성이 주요 신호로 보였다.

## 데이터 분할 원칙

기존 [split_dataset.py](/Users/gimminseog/project/quic-parse-csv/split_dataset.py)는 4-class 균형 분류용이므로 이상 탐지에는 그대로 쓰지 않는다.

이상 탐지용 split은 다음 원칙을 따라야 한다.

- train: `NORMAL` only
- valid: `NORMAL + ABNORMAL`
- test: `NORMAL + ABNORMAL`
- 분할 단위는 row가 아니라 `source_file` 또는 최소한 `file` 단위

이렇게 해야 같은 pcap에서 나온 유사 flow가 train/test에 동시에 섞이는 문제를 줄일 수 있다.

## 스키마 관련 주의점

빠르게 확인했을 때, 일부 `merged/*.csv`는 현재 `output/*.csv`보다 컬럼 수가 더 많아 stale schema 가능성이 있었다.

따라서 이상 탐지 파이프라인 구현 전에 다음을 먼저 수행하는 것이 안전하다.

1. `output` 기준으로 `merged`를 다시 생성
2. `merged_5.csv`, `merged_full.csv`의 컬럼 스키마 점검
3. leakage/identifier 컬럼 제거 목록 확정

## 구현 우선순위

### 1. 이상 탐지 split 스크립트 추가

예시 파일명:

- `split_anomaly_dataset.py`

역할:

- `merged_5.csv`, `merged_full.csv`를 읽기
- normal-only train / mixed valid / mixed test 생성
- 파일 단위 홀드아웃 보장

### 2. 이상 탐지 학습 스크립트 추가

예시 파일명:

- `train_anomaly_models.py`

역할:

- `LOF`, `IsolationForest`, `OneClassSVM` 학습
- 각 window별 score 저장
- threshold 저장
- ROC-AUC, PR-AUC, recall at target FPR 계산

### 3. 5/full 결합 평가 추가

역할:

- 동일 flow에 대한 `early_score`, `final_score` 결합
- `max`, `weighted sum` 등 간단한 조합 비교
- 최종 운영 threshold 선택

## 결론

현재 데이터 구조에서는 `merged_5`와 `merged_full`을 이용한 2단계 이상 탐지 전략이 가장 자연스럽다.

- `5`는 조기 경보
- `full`은 최종 확정
- 학습은 둘 다 `NORMAL`만 사용

초기 버전은 다음 조합으로 시작하는 것이 가장 실용적이다.

- `merged_5`: `LOF`
- `merged_full`: `IsolationForest`

그 다음 단계에서 threshold 정책과 score 결합 방식을 조정하면 된다.
