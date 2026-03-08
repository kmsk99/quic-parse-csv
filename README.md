# QUIC PCAP 특징 추출 및 이상 탐지 연구 도구

QUIC PCAP에서 flow/window 단위 특징을 추출하고, 분류 및 이상 탐지 실험까지 수행하기 위한 연구용 저장소입니다. 현재 저장소는 다음 두 흐름을 모두 지원합니다.

- 다중 클래스 분류용 데이터셋 생성 및 모델 학습
- `NORMAL`만 학습하는 one-class / anomaly detection 벤치마크

## 현재 상태

현재 코드베이스 기준으로 anomaly benchmark와 autoencoder 잠재공간 분석까지 포함한 최신 결과가 정리되어 있습니다.

- 종합 분석 문서: [docs/anomaly-analysis-summary.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-analysis-summary.md)
- benchmark 비교 문서: [docs/anomaly-benchmark-comparison.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-benchmark-comparison.md)
- autoencoder 잠재공간 문서: [docs/anomaly-autoencoder-latent.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-autoencoder-latent.md)
- 결과 CSV/plot: [prediction/anomaly_benchmark](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark)

현재 benchmark에서 가장 강한 모델은 `Autoencoder`였습니다.

| 단계 | 최고 모델 | 주요 수치 |
| --- | --- | --- |
| `merged_5.csv` | `Autoencoder` | recall `1.0000`, F1 `0.9995`, normal FPR `0.1204` |
| `merged_full.csv` | `Autoencoder` | recall `0.9908`, F1 `0.9950`, normal FPR `0.1002` |

고전적 baseline 중에서는 다음이 상대적으로 의미 있었습니다.

- 초기 단계: `HBOS`
- 최종 단계: `ECOD`
- reconstruction baseline: `PCAReconstruction`

`Autoencoder`의 bottleneck(`24차원`) 잠재공간도 별도로 시각화했습니다. `5패킷` 잠재공간은 정상/비정상이 꽤 잘 갈리지만, `full`에서는 특히 `SCAN`이 정상 군집 쪽으로 더 가까워지는 경향이 보입니다. 2D뿐 아니라 3D `png/html`도 같이 생성합니다.

## 주요 기능

- QUIC PCAP에서 flow/window 단위 CSV 생성
- packet window `1~30` 및 `full` 데이터셋 지원
- `source_file` 단위 분할 기반 anomaly benchmark
- 다중 클래스 분류용 dataset split 및 학습 파이프라인
- anomaly benchmark용 개별 모델 실행 스크립트 제공
- autoencoder bottleneck latent space 시각화
- autoencoder latent 3D `png/html` 생성
- ROC, PR, score distribution, attack recall, two-stage policy plot 생성

## 추출 특징 요약

현재 merged 데이터 기준으로 메타데이터를 제외한 수치 feature는 약 `176개`입니다. 주요 특징군은 다음과 같습니다.

- 패킷/바이트 수 통계
- 패킷 크기 통계
- IAT 통계
- short/long header, packet type 비율
- entropy 계열 특징
- QUIC packet length / payload length 통계
- spin bit / fixed bit / version 관련 특징
- DCID / SCID 길이 및 변화량 통계
- packet number 길이 및 gap 통계
- frame type count / ratio
- ACK delay 통계

## 프로젝트 구조

| 경로 | 역할 |
| :--- | :--- |
| `config.py` | 공통 경로, 패킷 윈도우, 라벨, 랜덤 시드 설정 |
| `pcap_to_csv.py` | PCAP에서 window별 CSV 추출 |
| `label_and_merge.py` | `output/` CSV를 병합하고 라벨 추가 |
| `split_dataset.py` | 다중 클래스 분류용 train/test/valid 분할 |
| `train_models.py` | 다중 클래스 분류 모델 학습 및 중요도 분석 |
| `train_anomaly_models.py` | 초기 one-class baseline 실험용 스크립트 |
| `scripts/run_anomaly_benchmarks.py` | anomaly benchmark 전체 실행 |
| `scripts/train_anomaly_*.py` | 모델별 anomaly benchmark 실행 스크립트 |
| `scripts/visualize_autoencoder_latent.py` | 학습된 autoencoder의 bottleneck 잠재공간 시각화 |
| `output/` | packet window별 원본 특징 CSV |
| `merged/` | window별 병합 CSV |
| `dataset/` | 분류용 train/test/valid 데이터셋 |
| `prediction/` | 분류 및 anomaly 실험 산출물 |
| `docs/` | 설계 문서, benchmark 비교 문서, 종합 분석 문서 |

## 설치

### 1. `uv` 설치

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 2. Wireshark (`tshark`) 설치

`tshark`가 시스템 PATH에 있어야 합니다.

```bash
# macOS
brew install wireshark

# Linux
sudo apt-get install tshark
```

### 3. 의존성 설치

```bash
uv sync
```

## 사용법

### 1. `.env` 설정

```bash
PCAP_ROOT_DIR=/path/to/your/quic/pcaps
```

필요하면 [config.py](/Users/gimminseog/project/quic-parse-csv/config.py)에서 패킷 윈도우, 라벨, 경로를 조정합니다.

### 2. 전처리 실행

PCAP에서 `output/`, `merged/`, `dataset/`까지 생성합니다.

```bash
chmod +x preprocess.sh
./preprocess.sh
```

### 3. 다중 클래스 분류 실험

```bash
uv run python train_models.py
```

산출물은 `prediction/<window>/` 아래에 저장됩니다.

### 4. anomaly benchmark 전체 실행

```bash
uv run python scripts/run_anomaly_benchmarks.py
```

산출물은 `prediction/anomaly_benchmark/` 아래에 저장됩니다.

### 5. anomaly benchmark 개별 실행

원하는 모델만 따로 돌릴 수도 있습니다.

```bash
uv run python scripts/train_anomaly_isolation_forest.py
uv run python scripts/train_anomaly_hbos.py
uv run python scripts/train_anomaly_ecod.py
uv run python scripts/train_anomaly_pca.py
uv run python scripts/train_anomaly_autoencoder.py
```

### 6. autoencoder 잠재공간 시각화

이미 학습된 autoencoder artifact를 재사용해서 bottleneck 잠재공간을 시각화합니다.

```bash
uv run python scripts/visualize_autoencoder_latent.py
```

산출물은 `prediction/anomaly_benchmark/autoencoder/{5,full}/`와 `docs/anomaly-autoencoder-latent.md`에 저장됩니다.

## anomaly benchmark 구성

현재 benchmark는 다음 조건으로 고정되어 있습니다.

- 학습 데이터: `NORMAL` only
- 검증/테스트 데이터: `NORMAL + ABNORMAL`
- 분할 단위: `source_file`
- 대상 데이터:
  - `merged_5.csv`
  - `merged_full.csv`

비교 모델:

- `IsolationForest`
- `HBOS`
- `ECOD`
- `PCAReconstruction`
- `Autoencoder`

2단계 정책도 함께 평가합니다.

- `early_warning`
- `final_confirmation`
- `any_stage`

## 최신 결과 요약

자세한 내용은 [docs/anomaly-analysis-summary.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-analysis-summary.md)에 정리되어 있습니다. 핵심만 요약하면 다음과 같습니다.

- `Autoencoder`가 초기 단계와 최종 단계 모두 가장 강했습니다.
- `HBOS`는 초기 단계 classical baseline으로는 의미가 있지만 정상 오탐이 높았습니다.
- `ECOD`는 초기 단계보다는 full-stage baseline으로 더 적합했습니다.
- `PCAReconstruction`은 초기 단계에는 부적합하지만 full-stage reconstruction baseline으로는 경쟁력이 있었습니다.
- `IsolationForest`는 이번 데이터에서는 가장 약한 baseline이었습니다.
- autoencoder bottleneck 시각화에서는 `5패킷` 잠재공간이 더 선명했고, `full`에서는 `SCAN`이 NORMAL과 가까워지는 경향이 관찰됐습니다.
- 3D PCA/t-SNE에서도 같은 경향이 유지됐고, `full`에서는 `SCAN`이 NORMAL 주변으로 다시 말려 들어오는 구조가 더 분명하게 보였습니다.

중요한 해석 포인트:

- aggregate PR-AUC만 보면 모델 차이가 작아 보일 수 있지만, 실제로는 공격 유형별 재현율 차이가 큽니다.
- validation에서 잡은 threshold가 test에서 그대로 유지되지 않는 경우가 많아서, score calibration과 더 강한 홀드아웃 검증이 필요합니다.
- 성능이 좋은 단일 모델이 있다고 해도 잠재공간 구조가 항상 깔끔한 것은 아니므로, reconstruction score와 latent geometry를 같이 보는 것이 해석에 유리합니다.

## Autoencoder 잠재공간 결과

잠재공간 결과는 README에서도 바로 확인할 수 있게 2D와 3D를 함께 남겨둡니다.

- `5패킷` latent는 정상/비정상 분리가 비교적 선명했습니다.
  - binary silhouette: `0.7038`
  - NORMAL centroid 대비 거리:
    - `GET_FLOOD 12.4369`
    - `CONNECTION_FLOOD 13.8504`
    - `SCAN 12.6275`
- `full` latent는 `SCAN`이 NORMAL 근처로 가까워졌습니다.
  - binary silhouette: `-0.1546`
  - NORMAL centroid 대비 거리:
    - `GET_FLOOD 7.3797`
    - `CONNECTION_FLOOD 6.1139`
    - `SCAN 1.3703`

### 5패킷 2D 결과

![5패킷 latent PCA 2D](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/5/latent_pca.png)

![5패킷 latent t-SNE 2D](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/5/latent_tsne.png)

### 5패킷 3D 결과

![5패킷 latent PCA 3D](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/5/latent_pca_3d.png)

![5패킷 latent t-SNE 3D](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/5/latent_tsne_3d.png)

- 인터랙티브 HTML:
  - [5패킷 PCA 3D HTML](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/5/latent_pca_3d.html)
  - [5패킷 t-SNE 3D HTML](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/5/latent_tsne_3d.html)

### 전체 flow 2D 결과

![전체 flow latent PCA 2D](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/full/latent_pca.png)

![전체 flow latent t-SNE 2D](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/full/latent_tsne.png)

### 전체 flow 3D 결과

![전체 flow latent PCA 3D](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/full/latent_pca_3d.png)

![전체 flow latent t-SNE 3D](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/full/latent_tsne_3d.png)

- 인터랙티브 HTML:
  - [전체 flow PCA 3D HTML](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/full/latent_pca_3d.html)
  - [전체 flow t-SNE 3D HTML](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/full/latent_tsne_3d.html)

## 주요 결과 파일

- benchmark 비교 CSV: [prediction/anomaly_benchmark/comparison/test_model_comparison.csv](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/comparison/test_model_comparison.csv)
- 정책 비교 CSV: [prediction/anomaly_benchmark/comparison/policy_comparison.csv](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/comparison/policy_comparison.csv)
- 비교 문서: [docs/anomaly-benchmark-comparison.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-benchmark-comparison.md)
- 종합 분석 문서: [docs/anomaly-analysis-summary.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-analysis-summary.md)
- autoencoder 잠재공간 문서: [docs/anomaly-autoencoder-latent.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-autoencoder-latent.md)
- 5패킷 latent PCA: [prediction/anomaly_benchmark/autoencoder/5/latent_pca.png](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/5/latent_pca.png)
- 전체 flow latent PCA: [prediction/anomaly_benchmark/autoencoder/full/latent_pca.png](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/full/latent_pca.png)
- 5패킷 latent PCA 3D HTML: [prediction/anomaly_benchmark/autoencoder/5/latent_pca_3d.html](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/5/latent_pca_3d.html)
- 전체 flow latent PCA 3D HTML: [prediction/anomaly_benchmark/autoencoder/full/latent_pca_3d.html](/Users/gimminseog/project/quic-parse-csv/prediction/anomaly_benchmark/autoencoder/full/latent_pca_3d.html)

모델별 문서:

- [docs/anomaly-autoencoder.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-autoencoder.md)
- [docs/anomaly-hbos.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-hbos.md)
- [docs/anomaly-ecod.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-ecod.md)
- [docs/anomaly-isolation-forest.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-isolation-forest.md)
- [docs/anomaly-pca-reconstruction.md](/Users/gimminseog/project/quic-parse-csv/docs/anomaly-pca-reconstruction.md)

## Data Leakage 방지 설계

이 저장소는 특징 추출 단계에서 미래 정보를 직접 참조하지 않도록 설계되어 있습니다.

1. **구조적 격리**
   전달된 packet slice만으로 특징을 계산하고, 전체 flow의 미래 패킷 정보를 직접 읽지 않습니다.

2. **메타데이터 분리**
   모델 학습 시 `file`, `flow_id`, IP/Port 같은 식별자 컬럼은 feature에서 제외합니다.

3. **파일 단위 홀드아웃**
   anomaly benchmark는 row가 아니라 `source_file` 단위로 분할해서 동일 capture에서 나온 유사 flow가 train/test에 동시에 섞이지 않게 합니다.

## 요구사항

- Python 3.10 이상
- Wireshark / tshark 4.0 이상
- `uv`

## 다음 권장 작업

1. `Autoencoder`의 threshold를 더 보수적으로 튜닝해서 normal FPR을 낮춥니다.
2. `source_file`보다 더 강한 홀드아웃 기준으로 일반화 성능을 다시 검증합니다.
3. 이후에는 packet size / direction / IAT sequence를 직접 쓰는 sequence anomaly detection으로 확장할 수 있습니다.
