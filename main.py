#!/usr/bin/env python3
"""
QUIC pcap 파일 분석 및 통계 생성 도구
각 QUIC flow의 전체 통계와 첫 5, 10, 15, 20개 패킷에 대한 통계를 계산합니다.
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Any
from dotenv import load_dotenv
import pyshark
import pandas as pd
from collections import defaultdict

# .env 파일 로드
load_dotenv()

# 설정
PCAP_ROOT_DIR = Path(os.getenv("PCAP_ROOT_DIR", "/Volumes/Lieutenant/quic"))
PACKET_WINDOWS = [5, 10, 15, 20]  # 분석할 패킷 개수


def find_first_pcap_in_folders(root_dir: Path) -> List[Path]:
    """
    각 서브폴더에서 첫 번째 pcap 파일을 찾아 반환합니다.
    
    Args:
        root_dir: pcap 파일들이 있는 루트 디렉토리
        
    Returns:
        각 폴더의 첫 번째 pcap 파일 경로 리스트
    """
    pcap_files = []
    
    if not root_dir.exists():
        print(f"경고: {root_dir} 디렉토리가 존재하지 않습니다.")
        return pcap_files
    
    # 루트 디렉토리의 모든 서브디렉토리 순회
    for item in sorted(root_dir.iterdir()):
        if item.is_dir():
            # 디렉토리 내의 pcap 파일들을 찾음
            pcaps_in_dir = sorted(item.glob("**/*.pcap"))
            if pcaps_in_dir:
                first_pcap = pcaps_in_dir[0]
                pcap_files.append(first_pcap)
                print(f"폴더 '{item.name}'에서 발견: {first_pcap.name}")
    
    return pcap_files


def extract_quic_flows(pcap_file: Path) -> Dict[str, List[Any]]:
    """
    pcap 파일에서 QUIC flow를 추출합니다.
    
    Args:
        pcap_file: 분석할 pcap 파일 경로
        
    Returns:
        flow_id를 키로 하는 패킷 리스트 딕셔너리
    """
    flows = defaultdict(list)
    
    print(f"\n파일 분석 중: {pcap_file.name}")
    
    try:
        # QUIC 패킷만 필터링 (UDP port 443 또는 QUIC 프로토콜)
        capture = pyshark.FileCapture(
            str(pcap_file),
            display_filter='quic || (udp.port == 443)',
            use_json=True,
            include_raw=True
        )
        
        packet_count = 0
        for packet in capture:
            packet_count += 1
            
            # Flow ID 생성 (src_ip:src_port -> dst_ip:dst_port)
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            else:
                continue
            
            if hasattr(packet, 'udp'):
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
            else:
                continue
            
            # 양방향 flow를 하나로 통합
            flow_id_1 = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            flow_id_2 = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
            
            # 정렬하여 일관된 flow_id 사용
            flow_id = min(flow_id_1, flow_id_2)
            
            flows[flow_id].append(packet)
        
        capture.close()
        print(f"  총 {packet_count}개 패킷, {len(flows)}개 flow 발견")
        
    except Exception as e:
        print(f"  오류 발생: {e}")
    
    return flows


def calculate_packet_statistics(packets: List[Any], num_packets: int = None) -> Dict[str, Any]:
    """
    패킷들의 통계를 계산합니다.
    
    Args:
        packets: 패킷 리스트
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
    
    for packet in packets:
        try:
            # 패킷 크기
            if hasattr(packet, 'length'):
                size = int(packet.length)
                packet_sizes.append(size)
                stats['total_bytes'] += size
                stats['min_packet_size'] = min(stats['min_packet_size'], size)
                stats['max_packet_size'] = max(stats['max_packet_size'], size)
            
            # 타임스탬프
            if hasattr(packet, 'sniff_timestamp'):
                timestamps.append(float(packet.sniff_timestamp))
                
        except Exception as e:
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


def analyze_pcap_file(pcap_file: Path) -> List[Dict[str, Any]]:
    """
    pcap 파일을 분석하고 모든 flow의 통계를 반환합니다.
    
    Args:
        pcap_file: 분석할 pcap 파일 경로
        
    Returns:
        각 flow의 통계를 담은 딕셔너리 리스트
    """
    results = []
    
    # QUIC flow 추출
    flows = extract_quic_flows(pcap_file)
    
    # 각 flow 분석
    for flow_id, packets in flows.items():
        flow_result = {
            'file': pcap_file.name,
            'flow_id': flow_id,
            'total_packets': len(packets),
        }
        
        # 전체 flow 통계
        full_stats = calculate_packet_statistics(packets)
        for key, value in full_stats.items():
            flow_result[f'full_{key}'] = value
        
        # 첫 N개 패킷 통계
        for n in PACKET_WINDOWS:
            if len(packets) >= n:
                window_stats = calculate_packet_statistics(packets, n)
                for key, value in window_stats.items():
                    flow_result[f'first_{n}_{key}'] = value
            else:
                # 패킷이 충분하지 않으면 None으로 표시
                for key in ['packet_count', 'total_bytes', 'avg_packet_size', 
                           'min_packet_size', 'max_packet_size', 'duration']:
                    flow_result[f'first_{n}_{key}'] = None
        
        results.append(flow_result)
        print(f"  Flow {flow_id}: {len(packets)} 패킷")
    
    return results


def main():
    """메인 함수"""
    print("QUIC pcap 파일 분석 시작")
    print(f"PCAP 루트 디렉토리: {PCAP_ROOT_DIR}")
    print("=" * 80)
    
    # 각 폴더에서 첫 번째 pcap 파일 찾기
    pcap_files = find_first_pcap_in_folders(PCAP_ROOT_DIR)
    
    if not pcap_files:
        print("분석할 pcap 파일을 찾을 수 없습니다.")
        return
    
    print(f"\n총 {len(pcap_files)}개의 pcap 파일을 분석합니다.")
    print("=" * 80)
    
    # 모든 결과 수집
    all_results = []
    
    for pcap_file in pcap_files:
        results = analyze_pcap_file(pcap_file)
        all_results.extend(results)
    
    # DataFrame으로 변환
    if all_results:
        df = pd.DataFrame(all_results)
        
        # CSV로 저장
        output_file = "quic_flow_statistics.csv"
        df.to_csv(output_file, index=False)
        print("\n" + "=" * 80)
        print(f"결과가 {output_file}에 저장되었습니다.")
        print(f"총 {len(all_results)}개의 flow를 분석했습니다.")
        
        # 요약 통계 출력
        print("\n요약 통계:")
        print(f"  - 평균 패킷 수 per flow: {df['total_packets'].mean():.2f}")
        print(f"  - 최대 패킷 수: {df['total_packets'].max()}")
        print(f"  - 최소 패킷 수: {df['total_packets'].min()}")
    else:
        print("\n분석된 flow가 없습니다.")


if __name__ == "__main__":
    main()
