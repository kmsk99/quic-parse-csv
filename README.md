# QUIC pcap 파일 분석 및 탐지 연구 도구

QUIC pcap 파일에서 각 flow의 **64개 특징**을 추출하고 머신러닝 모델을 훈련하는 통합 도구입니다. DDoS 공격 탐지 연구를 위한 논문 기반 특징 추출 및 분석 기능을 제공합니다.

**크로스 플랫폼 지원**: Windows, macOS, Linux에서 모두 실행 가능합니다.

## 기능

- **모듈형 파이프라인**: 특징 추출, 라벨링/병합, 데이터셋 분할, 모델 학습이 독립적인 모듈로 분리됨
- **Data Leakage 자동 방지**: 구조적 격리(Structural Isolation)를 통해 미래 정보가 학습 데이터에 포함되는 것을 원천 차단
- **QUIC flow 자동 감지 및 분리**
- **64개 특징 추출** (논문 기반):
  - **패킷 및 바이트 수**: 전체, incoming, outgoing
  - **패킷 크기 통계**: mean, min, max, std, variance, CV (전체/방향별)
  - **IAT (Inter-Arrival Time) 통계**: mean, min, max, std, variance (전체/방향별)
  - **QUIC 프로토콜 특징**: Spin Bit (count/ratio), 패킷 유형별 개수 및 비율 (Initial, Handshake, 0-RTT, 1-RTT, Retry)
  - **엔트로피**: 패킷 방향 및 크기 엔트로피
  - **Flow 메타데이터**: Duration, IP/Port, flow_id 등
- **윈도우 분석**: 전체 flow뿐만 아니라 초기 패킷(5, 10, 15, 20개) 기반 Early Classification 지원
- **tshark 직접 사용**: pyshark보다 10-50배 빠른 속도 및 낮은 메모리 사용량

## 프로젝트 구조

| 파일 | 역할 |
| :--- | :--- |
| `config.py` | **통합 설정**: 모든 경로, 라벨, 패킷 윈도우 크기 등을 한곳에서 관리 |
| `pcap_to_csv.py` | **추출**: PCAP 파일에서 64개 특징을 추출하여 CSV로 저장 (Leakage-free) |
| `label_and_merge.py` | **라벨링**: 파일명 기반 라벨 할당 및 지역 CSV 병합 |
| `split_dataset.py` | **분할**: 1:1:1:1 비율로 정답 라벨 균형을 맞춘 Train/Test/Valid 데이터셋 생성 |
| `train_models.py` | **학습 & XAI**: 여러 모델 학습 및 SHAP, Permutation Importance 분석 |
| `preprocess.sh` | **자동화**: PCAP에서 데이터셋 생성까지 모든 전처리 과정을 자동 실행 |

## 설치

### 1. uv 설치
[uv](https://github.com/astral-sh/uv)를 사용하여 의존성을 관리합니다.

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 2. Wireshark (tshark) 설치
`tshark`가 시스템 PATH에 있어야 합니다.

```bash
# macOS
brew install wireshark

# Linux
sudo apt-get install tshark
```

### 3. 프로젝트 의존성 설치
```bash
uv sync
```

## 사용법

### 1. 설정 (`config.py` & `.env`)
`.env` 파일에 PCAP 파일의 루트 경로를 설정합니다:
```bash
PCAP_ROOT_DIR=/path/to/your/quic/pcaps
```
필요한 경우 `config.py`에서 패킷 윈도우 크기(`PACKET_WINDOWS`)나 라벨 설정을 변경할 수 있습니다.

### 2. 데이터 전처리 (PCAP -> Dataset)
자동화된 쉘 스크립트를 사용하여 특징 추출부터 데이터셋 분할까지 완료합니다:
```bash
chmod +x preprocess.sh
./preprocess.sh
```

### 3. 모델 학습 및 분석
```bash
uv run python train_models.py
```
학습이 완료되면 `prediction/` 폴더에 모델 파일(`.pkl`), 학습 결과(`results.csv`), 그리고 SHAP 및 특징 중요도 그래프가 저장됩니다.

## Data Leakage 방지 설계

본 도구는 연구의 신뢰성을 위해 다음 두 단계의 누수 방지 로직을 강제합니다:

1.  **구조적 격리 (Structural Isolation)**: 특징 추출 함수(`calculate_comprehensive_statistics`)는 오직 전달받은 잘려진(sliced) 패킷 리스트에만 접근할 수 있습니다. 전체 Flow 길이나 미래의 패킷 정보를 물리적으로 알 수 없는 상태에서 계산됩니다.
2.  **화이트리스트 메타데이터**: 윈도우 데이터셋 생성 시 `total_packets_in_flow`와 같은 미래의 정보가 포함된 필드는 엄격히 제외됩니다.

## 요구사항

- Python 3.10 이상
- Wireshark/tshark 4.0 이상
- uv (패키지 관리자)

## 연구 참고

본 도구는 다음 특징을 기반으로 트래픽을 분석합니다:
- **Volume**: 패킷 및 바이트 수 통계
- **Packet Size**: 크기의 분포 및 무작위성(엔트로피)
- **Time (IAT)**: 패킷 간 도착 시간 간격
- **QUIC Specific**: Spin Bit 및 0-RTT/1-RTT 패킷 유형 분석
