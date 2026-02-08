#!/usr/bin/env python3
"""
QUIC pcap 파일 분석 및 통계 생성 도구
각 QUIC flow의 전체 통계와 첫 5, 10, 15, 20개 패킷에 대한 통계를 계산합니다.
tshark를 직접 사용하여 빠른 처리.
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
import pandas as pd
from collections import defaultdict
from tqdm import tqdm
import time
import subprocess

# .env 파일 로드
load_dotenv()

# 설정
PCAP_ROOT_DIR = Path(os.getenv("PCAP_ROOT_DIR", "/Volumes/Lieutenant/quic"))
OUTPUT_DIR = Path("output")
PACKET_WINDOWS = [5, 10, 15, 20]  # 분석할 패킷 개수

# 출력 폴더 구조
OUTPUT_FOLDERS = {
    'full': OUTPUT_DIR / 'full',
    5: OUTPUT_DIR / '5',
    10: OUTPUT_DIR / '10',
    15: OUTPUT_DIR / '15',
    20: OUTPUT_DIR / '20',
}


def setup_output_directories():
    """출력 디렉토리 구조를 생성합니다."""
    for folder in OUTPUT_FOLDERS.values():
        folder.mkdir(parents=True, exist_ok=True)


def find_first_pcap_in_folders(root_dir: Path) -> List[Path]:
    """
    모든 폴더(재귀적)에서 첫 번째 pcap 파일을 찾아 반환합니다.
    
    Args:
        root_dir: pcap 파일들이 있는 루트 디렉토리
        
    Returns:
        각 폴더의 첫 번째 pcap 파일 경로 리스트
    """
    pcap_files = []
    visited_dirs = set()
    
    if not root_dir.exists():
        print(f"경고: {root_dir} 디렉토리가 존재하지 않습니다.")
        return pcap_files
    
    def find_pcaps_recursive(directory: Path):
        """재귀적으로 각 폴더의 첫 번째 pcap 파일을 찾습니다."""
        if directory in visited_dirs:
            return
        visited_dirs.add(directory)
        
        # 현재 디렉토리에서 직접 찾은 pcap 파일들
        direct_pcaps = sorted([f for f in directory.glob("*.pcap") if f.is_file()])
        
        if direct_pcaps:
            # 현재 디렉토리에 pcap 파일이 있으면 첫 번째 파일만 추가
            pcap_files.append(direct_pcaps[0])
        else:
            # 현재 디렉토리에 pcap이 없으면 서브디렉토리 탐색
            subdirs = sorted([d for d in directory.iterdir() if d.is_dir()])
            for subdir in subdirs:
                find_pcaps_recursive(subdir)
    
    # 루트의 직접 서브디렉토리들을 순회
    subdirs = sorted([d for d in root_dir.iterdir() if d.is_dir()])
    for subdir in subdirs:
        find_pcaps_recursive(subdir)
    
    return pcap_files


def format_file_size(size_bytes: int) -> str:
    """
    파일 크기를 읽기 쉬운 형식으로 변환합니다.
    
    Args:
        size_bytes: 바이트 단위 크기
        
    Returns:
        포맷된 문자열 (예: "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def extract_quic_flows_tshark(pcap_file: Path) -> Dict[str, List[Dict[str, Any]]]:
    """
    tshark를 사용하여 pcap 파일에서 QUIC flow를 추출합니다.
    텍스트 필드 출력 모드 사용 (JSON보다 빠르고 안정적)
    
    Args:
        pcap_file: 분석할 pcap 파일 경로
        
    Returns:
        flow_id를 키로 하는 패킷 정보 딕셔너리 리스트
    """
    flows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    file_size = pcap_file.stat().st_size
    file_size_str = format_file_size(file_size)
    
    print(f"  📖 파일 읽기: {pcap_file.name} ({file_size_str})")
    
    try:
        # tshark 명령어 - 텍스트 필드 출력 모드 (더 빠르고 안정적)
        # -T fields: 필드 텍스트 출력
        # -E separator=,: CSV 형식
        # -E quote=d: 큰따옴표로 감싸기
        cmd = [
            'tshark',
            '-r', str(pcap_file),
            '-Y', 'quic || udp.port == 443',
            '-T', 'fields',
            '-E', 'separator=,',
            '-E', 'quote=d',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'ipv6.src',
            '-e', 'ipv6.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'frame.len',
            '-e', 'frame.time_epoch'
        ]
        
        # tshark 실행
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        # 출력 파싱
        lines = result.stdout.strip().split('\n')
        
        with tqdm(total=len(lines), desc="  패킷 처리", unit="pkt", leave=False) as pbar:
            for line in lines:
                if not line.strip():
                    continue
                
                # CSV 파싱 (따옴표 제거)
                fields = [f.strip('"').strip() for f in line.split(',')]
                
                if len(fields) < 8:
                    pbar.update(1)
                    continue
                
                # 필드 추출
                ip_src = fields[0]
                ip_dst = fields[1]
                ipv6_src = fields[2]
                ipv6_dst = fields[3]
                src_port = fields[4]
                dst_port = fields[5]
                frame_len = fields[6]
                time_epoch = fields[7]
                
                # IP 주소 결정 (IPv4 우선, 없으면 IPv6)
                src_ip = ip_src if ip_src else ipv6_src
                dst_ip = ip_dst if ip_dst else ipv6_dst
                
                # 필수 필드 체크
                if not src_ip or not dst_ip or not src_port or not dst_port:
                    pbar.update(1)
                    continue
                
                # 패킷 정보 생성
                try:
                    packet_info = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'size': int(frame_len) if frame_len else 0,
                        'timestamp': float(time_epoch) if time_epoch else 0.0
                    }
                except (ValueError, TypeError):
                    pbar.update(1)
                    continue
                
                # Flow ID 생성 (양방향 통합)
                flow_id_1 = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                flow_id_2 = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                flow_id = min(flow_id_1, flow_id_2)
                
                # Flow에 패킷 추가
                flows[flow_id].append(packet_info)
                
                pbar.update(1)
        
        print(f"  ✓ {len(flows)}개 flow, {len(lines)}개 패킷 발견")
        
    except subprocess.CalledProcessError as e:
        print(f"  ❌ tshark 실행 오류: {e.stderr}")
        raise
    except Exception as e:
        print(f"  ❌ 처리 오류: {e}")
        raise
    
    return flows


def calculate_packet_statistics(packets: List[Dict[str, Any]], num_packets: int = None) -> Dict[str, Any]:
    """
    패킷들의 통계를 계산합니다.
    
    Args:
        packets: 패킷 정보 딕셔너리 리스트
        num_packets: 분석할 패킷 개수 (None이면 전체)
        
    Returns:
        통계 딕셔너리
    """
    if num_packets:
        packets = packets[:num_packets]
    
    if not packets:
        return {}
    
    stats = {
        'packet_count': len(packets),
        'total_bytes': 0,
        'avg_packet_size': 0,
        'min_packet_size': float('inf'),
        'max_packet_size': 0,
        'duration': 0,
    }
    
    packet_sizes = []
    timestamps = []
    
    for packet_info in packets:
        try:
            # 패킷 크기
            size = packet_info.get('size', 0)
            if size > 0:
                packet_sizes.append(size)
                stats['total_bytes'] += size
                stats['min_packet_size'] = min(stats['min_packet_size'], size)
                stats['max_packet_size'] = max(stats['max_packet_size'], size)
            
            # 타임스탬프
            timestamp = packet_info.get('timestamp', 0)
            if timestamp > 0:
                timestamps.append(timestamp)
                
        except Exception:
            continue
    
    # 평균 계산
    if packet_sizes:
        stats['avg_packet_size'] = sum(packet_sizes) / len(packet_sizes)
    
    # Duration 계산
    if len(timestamps) >= 2:
        stats['duration'] = timestamps[-1] - timestamps[0]
    
    # 무한대 값 처리
    if stats['min_packet_size'] == float('inf'):
        stats['min_packet_size'] = 0
    
    return stats


def analyze_pcap_file(pcap_file: Path) -> Dict[str, int]:
    """
    pcap 파일을 분석하고 각 종류별로 CSV를 저장합니다.
    
    Args:
        pcap_file: 분석할 pcap 파일 경로
        
    Returns:
        처리된 flow 개수 딕셔너리
    """
    start_time = time.time()
    
    try:
        # QUIC flow 추출
        flows = extract_quic_flows_tshark(pcap_file)
        
        if not flows:
            print(f"  ⚠️  flow 없음")
            return {'full': 0, 5: 0, 10: 0, 15: 0, 20: 0}
        
        filename_base = pcap_file.stem
        
        # 전체 flow 통계 계산
        print(f"  ⚙️  전체 통계 계산 중...")
        full_results = []
        for flow_id, packets in tqdm(flows.items(), desc="  전체 flow", leave=False):
            flow_result = {
                'file': pcap_file.name,
                'flow_id': flow_id,
                'total_packets': len(packets),
            }
            
            # 전체 flow 통계
            full_stats = calculate_packet_statistics(packets)
            for key, value in full_stats.items():
                flow_result[key] = value
            
            full_results.append(flow_result)
        
        # 전체 통계 저장
        if full_results:
            df = pd.DataFrame(full_results)
            output_path = OUTPUT_FOLDERS['full'] / f"{filename_base}.csv"
            df.to_csv(output_path, index=False)
        
        # 각 윈도우 크기별로 통계 계산
        window_counts = {5: 0, 10: 0, 15: 0, 20: 0}
        
        for window in PACKET_WINDOWS:
            print(f"  ⚙️  첫 {window}개 패킷 통계 계산 중...")
            window_results = []
            
            for flow_id, packets in tqdm(flows.items(), desc=f"  첫 {window}개", leave=False):
                if len(packets) < window:
                    continue
                
                flow_result = {
                    'file': pcap_file.name,
                    'flow_id': flow_id,
                    'window_size': window,
                    'total_packets_in_flow': len(packets),
                }
                
                # 첫 N개 패킷 통계
                window_stats = calculate_packet_statistics(packets, window)
                for key, value in window_stats.items():
                    flow_result[key] = value
                
                window_results.append(flow_result)
                window_counts[window] += 1
            
            # 윈도우별 통계 저장
            if window_results:
                df = pd.DataFrame(window_results)
                output_path = OUTPUT_FOLDERS[window] / f"{filename_base}.csv"
                df.to_csv(output_path, index=False)
        
        elapsed = time.time() - start_time
        print(f"  ✓ 완료: {len(flows)} flows, {elapsed:.2f}초")
        
        return {'full': len(full_results), **window_counts}
        
    except Exception as e:
        print(f"  ❌ 오류: {str(e)}")
        return {'full': 0, 5: 0, 10: 0, 15: 0, 20: 0}


def main():
    """메인 함수"""
    print("=" * 80)
    print("QUIC pcap 파일 분석 시작 (tshark 직접 사용)")
    print(f"PCAP 루트 디렉토리: {PCAP_ROOT_DIR}")
    print(f"출력 디렉토리: {OUTPUT_DIR}")
    print("=" * 80)
    
    # 출력 디렉토리 구조 생성
    setup_output_directories()
    print("✓ 출력 폴더 구조 생성 완료")
    
    # 각 폴더에서 첫 번째 pcap 파일 찾기
    pcap_files = find_first_pcap_in_folders(PCAP_ROOT_DIR)
    
    if not pcap_files:
        print("❌ 분석할 pcap 파일을 찾을 수 없습니다.")
        return
    
    print(f"✓ {len(pcap_files)}개의 pcap 파일 발견")
    for pcap_file in pcap_files:
        print(f"  - {pcap_file.relative_to(PCAP_ROOT_DIR)}")
    
    print("\n" + "=" * 80)
    print("분석 시작...")
    print("=" * 80 + "\n")
    
    # 전체 진행 상황을 위한 카운터
    total_stats = {
        'full': 0,
        5: 0,
        10: 0,
        15: 0,
        20: 0
    }
    
    # 진행 표시줄과 함께 파일 처리
    for i, pcap_file in enumerate(pcap_files, 1):
        print(f"\n[{i}/{len(pcap_files)}] {pcap_file.name}")
        print("-" * 80)
        
        stats = analyze_pcap_file(pcap_file)
        
        # 통계 누적
        for key in total_stats:
            total_stats[key] += stats[key]
    
    # 최종 결과 출력
    print("\n" + "=" * 80)
    print("분석 완료!")
    print("=" * 80)
    print(f"\n처리된 Flow 통계:")
    print(f"  - 전체 (full): {total_stats['full']} flows")
    for window in PACKET_WINDOWS:
        print(f"  - 첫 {window}개 패킷: {total_stats[window]} flows")
    
    print(f"\n결과 저장 위치:")
    for window_name, folder in OUTPUT_FOLDERS.items():
        csv_count = len(list(folder.glob("*.csv")))
        print(f"  - {folder}: {csv_count}개 CSV 파일")
    
    print("\n✓ 모든 작업이 완료되었습니다!")


if __name__ == "__main__":
    main()
