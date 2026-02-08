# QUIC pcap 파일 분석 도구

QUIC pcap 파일에서 각 flow의 전체 통계와 첫 5, 10, 15, 20개 패킷에 대한 통계를 추출하는 Python 도구입니다.

## 기능

- 각 폴더에서 첫 번째 pcap 파일 자동 탐색
- QUIC flow 자동 감지 및 분리
- 각 flow에 대한 상세 통계:
  - 전체 flow 통계 (패킷 수, 총 바이트, 평균/최소/최대 패킷 크기, 지속 시간)
  - 첫 5, 10, 15, 20개 패킷에 대한 동일한 통계
- CSV 형식으로 결과 저장

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

## 출력

프로그램은 `quic_flow_statistics.csv` 파일을 생성하며, 다음 정보를 포함합니다:

- `file`: 원본 pcap 파일명
- `flow_id`: flow 식별자 (src_ip:port->dst_ip:port)
- `total_packets`: flow의 총 패킷 수
- `full_*`: 전체 flow의 통계
- `first_5_*`, `first_10_*`, `first_15_*`, `first_20_*`: 첫 N개 패킷의 통계

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

## 프로젝트 구조

```
quic-parse-csv/
├── main.py              # 메인 분석 스크립트
├── pyproject.toml       # uv 의존성 설정
├── .env                 # 환경 변수 (pcap 경로)
├── .gitignore          # Git 무시 파일
└── README.md           # 이 파일
```
