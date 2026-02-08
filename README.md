# QUIC pcap 파일 분석 도구

QUIC pcap 파일에서 각 flow의 전체 통계와 첫 5, 10, 15, 20개 패킷에 대한 통계를 추출하는 고성능 병렬 처리 Python 도구입니다.

## 기능

- **재귀적 폴더 탐색**: 모든 depth의 폴더에서 첫 번째 pcap 파일 자동 탐색
- QUIC flow 자동 감지 및 분리
- **8개 워커를 사용한 멀티스레드 병렬 처리**
- **작은 청크 단위 처리**: 각 워커는 최대 10개 flow씩 처리 (1분 이내 완료 목표)
- **실시간 진행 상황 표시 (tqdm)**
- 각 flow에 대한 상세 통계:
  - 전체 flow 통계 (패킷 수, 총 바이트, 평균/최소/최대 패킷 크기, 지속 시간)
  - 첫 5, 10, 15, 20개 패킷에 대한 동일한 통계
- **파일별 즉시 CSV 저장** (메모리 효율적)
- **종류별 폴더 구조** (`output/full`, `output/5`, `output/10`, `output/15`, `output/20`)

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

## 출력 구조

프로그램은 다음과 같은 폴더 구조로 CSV 파일을 생성합니다:

```
output/
├── full/          # 전체 flow 통계
│   ├── recording_1.csv
│   ├── normal_traffic_recording_11.csv
│   └── ...
├── 5/             # 첫 5개 패킷 통계
│   ├── recording_1.csv
│   └── ...
├── 10/            # 첫 10개 패킷 통계
├── 15/            # 첫 15개 패킷 통계
└── 20/            # 첫 20개 패킷 통계
```

### CSV 파일 형식

**전체 통계 (`output/full/`)**:
- `file`: 원본 pcap 파일명
- `flow_id`: flow 식별자 (src_ip:port->dst_ip:port)
- `total_packets`: flow의 총 패킷 수
- `packet_count`, `total_bytes`, `avg_packet_size`, `min_packet_size`, `max_packet_size`, `duration`

**윈도우 통계 (`output/5/`, `10/`, `15/`, `20/`)**:
- `file`: 원본 pcap 파일명
- `flow_id`: flow 식별자
- `window_size`: 윈도우 크기 (5, 10, 15, 20)
- `total_packets_in_flow`: flow 전체의 패킷 수
- `packet_count`, `total_bytes`, `avg_packet_size`, `min_packet_size`, `max_packet_size`, `duration`

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
  - JSON 출력으로 필요한 필드만 추출
  - 2.3GB 파일: 90분 → 5-10분
- **경량 패킷 정보 저장**: 패킷 객체 전체가 아닌 필요한 정보만 딕셔너리로 저장
  - 메모리 사용량 90% 이상 감소 (3GB 파일 기준)
  - 패킷 객체의 무거운 메타데이터 제거
  - 처리 속도 10-100배 향상
- **파이프라인 병렬 처리**: 패킷 읽기와 flow 분류를 분리하여 동시에 처리
  - 패킷 읽기 스레드: 파일에서 패킷을 읽어 큐에 넣기
  - Flow 분류 워커들: 큐에서 패킷을 가져와서 flow로 분류 (8개 워커)
  - 읽기와 처리가 동시에 일어나 전체 처리 시간 단축
- **병렬 처리**: 각 파일의 flow들을 8개 워커로 병렬 처리
- **청크 분할**: Flow를 10개씩 묶어서 워커에게 할당 (워커당 1분 이내 처리 목표)
- **즉시 저장**: 각 파일 분석 완료 즉시 CSV 저장 (메모리 효율)
- **스레드 안전**: 파일 쓰기 시 락(Lock)을 사용하여 동시성 보장
- **진행 표시**: tqdm을 사용한 실시간 진행 상황 및 속도 표시
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
NUM_WORKERS = 8  # 워커 수 (CPU 코어 수에 따라 조정)
MAX_FLOWS_PER_CHUNK = 10  # 각 워커가 처리할 최대 flow 개수
PACKET_QUEUE_SIZE = 1000  # 패킷 큐 크기 (파이프라인 버퍼)
PACKET_WINDOWS = [5, 10, 15, 20]  # 분석할 패킷 윈도우 크기
```

### 성능 튜닝 팁

- **NUM_WORKERS**: CPU 코어 수에 맞게 조정 (일반적으로 코어 수와 동일하거나 2배)
- **PACKET_QUEUE_SIZE**: 메모리가 충분하면 더 크게 설정 (2000-5000)하여 읽기 속도 향상
- **MAX_FLOWS_PER_CHUNK**: 워커당 처리 시간이 너무 길면 더 작게 (5-8), 너무 짧으면 더 크게 (15-20)
