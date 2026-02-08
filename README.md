# QUIC pcap 파일 분석 도구

QUIC pcap 파일에서 각 flow의 **64개 특징**을 추출하는 Python 도구입니다. DDoS 공격 탐지 연구를 위한 논문 기반 특징 추출.

## 기능

- **재귀적 폴더 탐색**: 모든 depth의 폴더에서 첫 번째 pcap 파일 자동 탐색
- **QUIC flow 자동 감지 및 분리**
- **64개 특징 추출** (논문 기반):
  
  ### 1. 패킷 및 바이트 수 통계 (6개)
  - 전체, incoming, outgoing 패킷 수
  - 전체, incoming, outgoing 바이트 수
  
  ### 2. 패킷 크기 통계 (18개)
  - 전체, incoming, outgoing 각각:
    - mean, min, max, std, variance, coefficient of variation
  
  ### 3. IAT (Inter-Arrival Time) 통계 (15개)
  - 전체, incoming, outgoing 각각:
    - mean, min, max, std, variance
  
  ### 4. QUIC 프로토콜 특징 (13개)
  - Spin Bit: count, ratio, no_spin_bit_ratio
  - 패킷 유형별 개수: Initial, Handshake, 0-RTT, 1-RTT, Retry
  - 패킷 유형별 비율: Initial, Handshake, 0-RTT, 1-RTT, Retry
  
  ### 5. 엔트로피 및 복잡도 (2개)
  - 패킷 방향 엔트로피
  - 패킷 크기 엔트로피
  
  ### 6. Flow 메타데이터 (10개)
  - Duration, client/server IP/Port, flow_id, file name, window size
  
- **윈도우 분석**: 전체 + 첫 5, 10, 15, 20개 패킷에 대한 통계
- **tshark 직접 사용**: pyshark보다 10-50배 빠른 속도
- **즉시 저장**: 각 파일 분석 완료 즉시 CSV 저장
- **종류별 폴더 구조**: `output/full`, `output/5`, `output/10`, `output/15`, `output/20`

## 설치

uv를 사용하여 의존성을 설치합니다:

```bash
# uv 설치 (아직 설치하지 않은 경우)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 프로젝트 의존성 설치
uv sync
```

## 설정

`.env` 파일에서 pcap 파일 경로를 설정합니다:

```bash
PCAP_ROOT_DIR=/Volumes/Lieutenant/quic
```

## 사용법

```bash
# uv로 실행
uv run python main.py

# 또는 가상환경 활성화 후 실행
uv sync
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python main.py
```

## CSV 파일 형식

**전체 통계 (`output/full/`)**:
- `file`: 원본 pcap 파일명
- `flow_id`: flow 식별자
- `client_ip`, `client_port`: 클라이언트 정보
- `server_ip`, `server_port`: 서버 정보
- 64개 특징 (패킷 수, 바이트 수, 크기 통계, IAT, QUIC 특징, 엔트로피 등)

**윈도우 통계 (`output/5/`, `10/`, `15/`, `20/`)**:
- 위 필드 + `window_size`, `total_packets_in_flow`
- 첫 N개 패킷에 대한 64개 특징

## 특징 목록 (64개)

### 패킷 및 바이트 수 (6개)
```
total_packets, outgoing_packets, incoming_packets
total_bytes, outgoing_bytes, incoming_bytes
```

### 패킷 크기 통계 (18개)
```
packet_size_mean, packet_size_min, packet_size_max, packet_size_std, packet_size_var, packet_size_cv
packet_size_out_mean, packet_size_out_min, packet_size_out_max, packet_size_out_std, packet_size_out_var, packet_size_out_cv
packet_size_in_mean, packet_size_in_min, packet_size_in_max, packet_size_in_std, packet_size_in_var, packet_size_in_cv
```

### IAT 통계 (15개)
```
iat_mean, iat_min, iat_max, iat_std, iat_var
iat_out_mean, iat_out_min, iat_out_max, iat_out_std, iat_out_var
iat_in_mean, iat_in_min, iat_in_max, iat_in_std, iat_in_var
```

### QUIC 프로토콜 특징 (13개)
```
spin_bit_count, spin_bit_ratio, no_spin_bit_ratio
initial_packets, handshake_packets, zerortt_packets, onertt_packets, retry_packets
initial_ratio, handshake_ratio, zerortt_ratio, onertt_ratio, retry_ratio
```

### 엔트로피 (2개)
```
entropy_direction, entropy_packet_size
```

### Flow 메타데이터 (10개)
```
duration, client_ip, client_port, server_ip, server_port
flow_id, file, window_size, total_packets_in_flow
```

## 요구사항

- Python 3.10 이상
- Wireshark/tshark (pyshark가 내부적으로 사용)

### macOS에서 tshark 설치

```bash
brew install wireshark
```

### Linux에서 tshark 설치

```bash
sudo apt-get install tshark  # Ubuntu/Debian
sudo yum install wireshark    # CentOS/RHEL
```

## 성능 최적화

- **tshark 직접 사용**: pyshark 대신 tshark를 직접 호출하여 10-50배 속도 향상
  - pyshark: Python 래퍼로 인한 오버헤드
  - tshark 직접 사용: C 네이티브 코드로 최대 속도
  - 텍스트 필드 출력으로 안정적인 파싱
  - 2.3GB 파일: 90분 → 5-10분
- **경량 패킷 정보 저장**: 패킷 객체 전체가 아닌 필요한 정보만 딕셔너리로 저장
  - 메모리 사용량 90% 이상 감소
  - QUIC 프로토콜 특정 필드 포함 (spin_bit, packet_type, header_form)
- **즉시 저장**: 각 파일 분석 완료 즉시 CSV 저장 (메모리 효율)
- **진행 표시**: tqdm을 사용한 실시간 진행 상황 표시
- **재귀적 탐색**: 모든 depth의 폴더에서 pcap 파일 자동 발견

### 성능 개선 효과

**2.3GB 파일 기준**:
- **이전 (pyshark)**: 90분+ 소요, 메모리 수십 GB 사용, 읽기 속도 458KB/s
- **개선 후 (tshark)**: 5-10분 소요, 메모리 수백 MB 사용, 읽기 속도 5-20MB/s
- **속도 향상**: 10-20배 빠름
- **메모리 절감**: 90% 이상 감소
- **읽기 속도**: 10-40배 향상

## 프로젝트 구조

```
quic-parse-csv/
├── main.py              # 메인 분석 스크립트 (병렬 처리)
├── pyproject.toml       # uv 의존성 설정
├── .env                 # 환경 변수 (pcap 경로)
├── .gitignore          # Git 무시 파일
├── README.md           # 이 파일
└── output/             # 결과 CSV 파일 (자동 생성)
    ├── full/
    ├── 5/
    ├── 10/
    ├── 15/
    └── 20/
```

## 설정 변경

`main.py` 상단에서 다음 설정을 변경할 수 있습니다:

```python
PACKET_WINDOWS = [5, 10, 15, 20]  # 분석할 패킷 윈도우 크기
```

## 연구 참고

이 도구는 다음 논문의 특징 추출 방법을 기반으로 합니다:
- DDoS 공격 탐지를 위한 QUIC 트래픽 분석
- 64개 특징: Volume, Packet Size, IAT, QUIC-Specific, Entropy
- 주요 특징: 패킷 방향 엔트로피, Spin Bit 비율, IAT, 패킷 개수
