
#!/usr/bin/env python3
"""
QUIC pcap 파일 분석 및 통계 생성 도구
각 QUIC flow의 전체 통계와 첫 5, 10, 15, 20개 패킷에 대한 통계를 계산합니다.
tshark를 직접 사용하여 빠른 처리.
"""

import os
import sys
import platform
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd
from collections import defaultdict
from tqdm import tqdm
import time
import subprocess
import numpy as np

# Configuration Import
import config

# --- Use config constants ---
PCAP_ROOT_DIR = config.PCAP_ROOT_DIR
OUTPUT_DIR = config.OUTPUT_DIR
PACKET_WINDOWS = config.PACKET_WINDOWS
TSHARK_CMD = config.TSHARK_CMD
OUTPUT_FOLDERS = config.OUTPUT_FOLDERS


def find_all_pcap_files(root_dir: Path) -> List[Path]:
    """
    모든 폴더(재귀적)에서 모든 pcap 파일을 찾아 반환합니다.
    """
    pcap_files = []
    
    if not root_dir.exists():
        print(f"경고: {root_dir} 디렉토리가 존재하지 않습니다.")
        return pcap_files
    
    # 재귀적으로 모든 pcap 파일 찾기
    pcap_files = sorted(root_dir.rglob("*.pcap"))
    
    # 파일만 필터링 (디렉토리 제외)
    pcap_files = [f for f in pcap_files if f.is_file()]
    
    return pcap_files


def format_file_size(size_bytes: int) -> str:
    """파일 크기를 읽기 쉬운 형식으로 변환합니다."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def extract_quic_flows_tshark(pcap_file: Path) -> Dict[str, List[Dict[str, Any]]]:
    """
    tshark를 사용하여 pcap 파일에서 QUIC flow를 추출합니다.
    """
    flows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    file_size = pcap_file.stat().st_size
    file_size_str = format_file_size(file_size)
    
    print(f"  📖 파일 읽기: {pcap_file.name} ({file_size_str})")
    
    try:
        # tshark 명령어 - QUIC 프로토콜 특정 필드 추가
        cmd = [
            TSHARK_CMD,
            '-r', str(pcap_file),
            '-Y', 'quic || udp.port == 443',
            '-T', 'fields',
            '-E', 'separator=|',
            '-E', 'quote=d',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'ipv6.src',
            '-e', 'ipv6.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'frame.len',
            '-e', 'frame.time_epoch',
            '-e', 'quic.long.packet_type',
            '-e', 'quic.packet_length',
            '-e', 'quic.version',
            '-e', 'quic.dcid',
            '-e', 'quic.scid'
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
                
                # 파이프로 구분된 필드 파싱 (따옴표 제거)
                fields = [f.strip('"').strip() for f in line.split('|')]
                
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
                
                # QUIC 프로토콜 특정 필드 (인덱스 8부터)
                packet_type = fields[8] if len(fields) > 8 else ''
                quic_length = fields[9] if len(fields) > 9 else ''
                quic_version = fields[10] if len(fields) > 10 else ''
                dcid = fields[11] if len(fields) > 11 else ''
                scid = fields[12] if len(fields) > 12 else ''
                
                # IP 주소 결정 (IPv4 우선, 없으면 IPv6)
                src_ip = ip_src if ip_src else ipv6_src
                dst_ip = ip_dst if ip_dst else ipv6_dst
                
                # 필수 필드 체크
                if not src_ip or not dst_ip or not src_port or not dst_port:
                    pbar.update(1)
                    continue
                
                # Spin bit 추출 (Short header 패킷에만 존재, 여기서는 패킷 타입으로 추정)
                has_long_header = bool(packet_type)
                
                # 패킷 정보 생성
                try:
                    packet_info = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'size': int(frame_len) if frame_len else 0,
                        'timestamp': float(time_epoch) if time_epoch else 0.0,
                        'packet_type': packet_type.lower() if packet_type else '',
                        'is_long_header': has_long_header,
                        'is_short_header': not has_long_header,
                        'quic_length': int(quic_length) if quic_length else 0,
                        'quic_version': quic_version,
                        'dcid': dcid,
                        'scid': scid
                    }
                except (ValueError, TypeError):
                    pbar.update(1)
                    continue
                
                # Flow ID 생성 (양방향 통합)
                flow_id_1 = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                flow_id_2 = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                flow_id = min(flow_id_1, flow_id_2)
                
                # 첫 번째 패킷의 방향을 기준으로 저장
                if flow_id not in flows:
                    flows[flow_id] = {
                        'packets': [],
                        'server_ip': None,
                        'server_port': None,
                        'client_ip': None,
                        'client_port': None
                    }
                
                packet_info['direction'] = None
                flows[flow_id]['packets'].append(packet_info)
                
                pbar.update(1)
        
        print(f"  ✓ {len(flows)}개 flow, {len(lines)}개 패킷 발견")
        
        # 각 flow의 방향 정보 설정 (첫 패킷 기준)
        for flow_id, flow_data in flows.items():
            packets = flow_data['packets']
            if not packets:
                continue
            
            # 첫 패킷의 src를 클라이언트로 가정
            first_packet = packets[0]
            flow_data['client_ip'] = first_packet['src_ip']
            flow_data['client_port'] = first_packet['src_port']
            flow_data['server_ip'] = first_packet['dst_ip']
            flow_data['server_port'] = first_packet['dst_port']
            
            # 모든 패킷에 방향 정보 추가
            for packet in packets:
                if (packet['src_ip'] == flow_data['client_ip'] and 
                    packet['src_port'] == flow_data['client_port']):
                    packet['direction'] = 'outgoing'
                else:
                    packet['direction'] = 'incoming'
        
    except subprocess.CalledProcessError as e:
        print(f"  ❌ tshark 실행 오류: {e.stderr}")
        raise
    except Exception as e:
        print(f"  ❌ 처리 오류: {e}")
        raise
    
    return flows


def calculate_entropy(values: List[Any]) -> float:
    """엔트로피를 계산합니다."""
    if not values:
        return 0.0
    
    # 값의 빈도 계산
    from collections import Counter
    counts = Counter(values)
    total = len(values)
    
    # 엔트로피 계산
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * np.log2(probability)
    
    return entropy


def calculate_comprehensive_statistics(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    64개 특징을 포함한 포괄적인 통계를 계산합니다.
    [STRUCTURAL LEAKAGE PROTECTION] 이 함수는 전달받은 패킷 리스트 전체만 처리하며, 
    외부의 전체 Flow 정보에 접근할 수 없습니다.
    """
    if not packets:
        return {}
    
    stats = {}
    
    # 방향별로 패킷 분리
    all_packets = packets
    outgoing_packets = [p for p in packets if p.get('direction') == 'outgoing']
    incoming_packets = [p for p in packets if p.get('direction') == 'incoming']
    
    # === 1. 패킷 및 바이트 수 통계 ===
    stats['total_packets'] = len(all_packets)
    stats['outgoing_packets'] = len(outgoing_packets)
    stats['incoming_packets'] = len(incoming_packets)
    
    stats['total_bytes'] = sum(p.get('size', 0) for p in all_packets)
    stats['outgoing_bytes'] = sum(p.get('size', 0) for p in outgoing_packets)
    stats['incoming_bytes'] = sum(p.get('size', 0) for p in incoming_packets)
    
    # === 2. 패킷 크기 통계 (전체, incoming, outgoing) ===
    def calc_size_stats(pkts, prefix):
        sizes = [p.get('size', 0) for p in pkts if p.get('size', 0) > 0]
        if not sizes:
            stats[f'{prefix}_mean'] = 0
            stats[f'{prefix}_min'] = 0
            stats[f'{prefix}_max'] = 0
            stats[f'{prefix}_std'] = 0
            stats[f'{prefix}_var'] = 0
            stats[f'{prefix}_cv'] = 0
            return
        
        stats[f'{prefix}_mean'] = np.mean(sizes)
        stats[f'{prefix}_min'] = np.min(sizes)
        stats[f'{prefix}_max'] = np.max(sizes)
        stats[f'{prefix}_std'] = np.std(sizes)
        stats[f'{prefix}_var'] = np.var(sizes)
        stats[f'{prefix}_cv'] = np.std(sizes) / np.mean(sizes) if np.mean(sizes) > 0 else 0
    
    calc_size_stats(all_packets, 'packet_size')
    calc_size_stats(outgoing_packets, 'packet_size_out')
    calc_size_stats(incoming_packets, 'packet_size_in')
    
    # === 3. IAT (Inter-Arrival Time) 통계 ===
    def calc_iat_stats(pkts, prefix):
        timestamps = sorted([p.get('timestamp', 0) for p in pkts if p.get('timestamp', 0) > 0])
        if len(timestamps) < 2:
            stats[f'{prefix}_mean'] = 0
            stats[f'{prefix}_min'] = 0
            stats[f'{prefix}_max'] = 0
            stats[f'{prefix}_std'] = 0
            stats[f'{prefix}_var'] = 0
            return
        
        iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        stats[f'{prefix}_mean'] = np.mean(iats)
        stats[f'{prefix}_min'] = np.min(iats)
        stats[f'{prefix}_max'] = np.max(iats)
        stats[f'{prefix}_std'] = np.std(iats)
        stats[f'{prefix}_var'] = np.var(iats)
    
    calc_iat_stats(all_packets, 'iat')
    calc_iat_stats(outgoing_packets, 'iat_out')
    calc_iat_stats(incoming_packets, 'iat_in')
    
    # === 4. QUIC 프로토콜 특정 특징 ===
    short_header_packets = [p for p in all_packets if p.get('is_short_header', False)]
    long_header_packets = [p for p in all_packets if p.get('is_long_header', False)]
    
    stats['short_header_count'] = len(short_header_packets)
    stats['long_header_count'] = len(long_header_packets)
    stats['short_header_ratio'] = len(short_header_packets) / len(all_packets) if all_packets else 0
    stats['long_header_ratio'] = len(long_header_packets) / len(all_packets) if all_packets else 0
    
    stats['spin_bit_count'] = 0
    stats['spin_bit_ratio'] = 0.0
    stats['no_spin_bit_ratio'] = 1.0
    
    for pkt in all_packets:
        ptype = pkt.get('packet_type', '').lower()
        
        if 'initial' in ptype or ptype == '0':
            stats['initial_packets'] = stats.get('initial_packets', 0) + 1
        elif 'handshake' in ptype or ptype == '2':
            stats['handshake_packets'] = stats.get('handshake_packets', 0) + 1
        elif '0-rtt' in ptype or 'zerortt' in ptype or ptype == '1':
            stats['zerortt_packets'] = stats.get('zerortt_packets', 0) + 1
        elif 'retry' in ptype or ptype == '3':
            stats['retry_packets'] = stats.get('retry_packets', 0) + 1
        elif pkt.get('is_short_header', False):
            stats['onertt_packets'] = stats.get('onertt_packets', 0) + 1
    
    for key in ['initial_packets', 'handshake_packets', 'zerortt_packets', 
                'onertt_packets', 'retry_packets']:
        if key not in stats:
            stats[key] = 0
    
    total = len(all_packets)
    if total > 0:
        stats['initial_ratio'] = stats['initial_packets'] / total
        stats['handshake_ratio'] = stats['handshake_packets'] / total
        stats['zerortt_ratio'] = stats['zerortt_packets'] / total
        stats['onertt_ratio'] = stats['onertt_packets'] / total
        stats['retry_ratio'] = stats['retry_packets'] / total
    else:
        stats['initial_ratio'] = 0
        stats['handshake_ratio'] = 0
        stats['zerortt_ratio'] = 0
        stats['onertt_ratio'] = 0
        stats['retry_ratio'] = 0
    
    # === 5. 엔트로피 특징 ===
    directions = [p.get('direction', 'unknown') for p in all_packets]
    stats['entropy_direction'] = calculate_entropy(directions)
    
    sizes_binned = [p.get('size', 0) // 10 for p in all_packets]
    stats['entropy_packet_size'] = calculate_entropy(sizes_binned)
    
    # === 6. Flow Duration ===
    timestamps = [p.get('timestamp', 0) for p in all_packets if p.get('timestamp', 0) > 0]
    if len(timestamps) >= 2:
        stats['duration'] = max(timestamps) - min(timestamps)
    else:
        stats['duration'] = 0
    
    return stats


def analyze_pcap_file(pcap_file: Path) -> Dict[str, int]:
    """pcap 파일을 분석하고 각 종류별로 CSV를 저장합니다."""
    start_time = time.time()
    
    try:
        # QUIC flow 추출
        flows_data = extract_quic_flows_tshark(pcap_file)
        
        if not flows_data:
            print(f"  ⚠️  flow 없음")
            return {'full': 0, 5: 0, 10: 0, 15: 0, 20: 0}
        
        filename_base = pcap_file.stem
        
        # 전체 flow 통계 계산
        print(f"  ⚙️  전체 통계 계산 중 (64개 특징)...")
        full_results = []
        for flow_id, flow_data in tqdm(flows_data.items(), desc="  전체 flow", leave=False):
            packets = flow_data['packets']
            
            flow_result = {
                'file': pcap_file.name,
                'flow_id': flow_id,
                'client_ip': flow_data.get('client_ip', ''),
                'client_port': flow_data.get('client_port', ''),
                'server_ip': flow_data.get('server_ip', ''),
                'server_port': flow_data.get('server_port', ''),
            }
            
            # 64개 특징 계산
            full_stats = calculate_comprehensive_statistics(packets)
            flow_result.update(full_stats)
            
            full_results.append(flow_result)
        
        # 전체 통계 저장
        if full_results:
            df = pd.DataFrame(full_results)
            output_path = OUTPUT_FOLDERS['full'] / f"{filename_base}.csv"
            df.to_csv(output_path, index=False)
            print(f"    ✓ {output_path}")
        
        # 각 윈도우 크기별로 통계 계산
        window_counts = {str(w): 0 for w in PACKET_WINDOWS}
        
        # [LEAKAGE PROTECTION] Windowed 데이터에 포함될 안전한 메타데이터만 정의
        def get_safe_metadata(flow_id, flow_data, window):
            return {
                'file': pcap_file.name,
                'flow_id': flow_id,
                'window_size': window,
                'client_ip': flow_data.get('client_ip', ''),
                'client_port': flow_data.get('client_port', ''),
                'server_ip': flow_data.get('server_ip', ''),
                'server_port': flow_data.get('server_port', ''),
            }

        for window in PACKET_WINDOWS:
            print(f"  ⚙️  첫 {window}개 패킷 통계 계산 중...")
            window_results = []
            
            for flow_id, flow_data in tqdm(flows_data.items(), desc=f"  첫 {window}개", leave=False):
                packets = flow_data['packets']
                
                if len(packets) < window:
                    continue
                
                # [STRUCTURAL ISOLATION] 패킷을 먼저 자른 후 통계 함수에 전달
                # 이렇게 함으로써 통계 함수는 미래의 패킷 정보에 접근할 수 없습니다.
                windowed_packets = packets[:window]
                
                # 메타데이터 생성 (미래 정보인 total_packets_in_flow 등이 포함되지 않음)
                flow_result = get_safe_metadata(flow_id, flow_data, window)
                
                # 잘려진 패킷들만을 대상으로 통계 계산
                window_stats = calculate_comprehensive_statistics(windowed_packets)
                flow_result.update(window_stats)
                
                window_results.append(flow_result)
                window_counts[str(window)] += 1
            
            # 윈도우별 통계 저장
            if window_results:
                df = pd.DataFrame(window_results)
                output_path = OUTPUT_FOLDERS[str(window)] / f"{filename_base}.csv"
                df.to_csv(output_path, index=False)
                print(f"    ✓ {output_path}")
        
        elapsed = time.time() - start_time
        print(f"  ✓ 완료: {len(flows_data)} flows, {elapsed:.2f}초")
        
        return {'full': len(full_results), **window_counts}
        
    except Exception as e:
        print(f"  ❌ 오류: {str(e)}")
        import traceback
        traceback.print_exc()
        return {'full': 0, 5: 0, 10: 0, 15: 0, 20: 0}


def main():
    """메인 함수"""
    print("=" * 80)
    print("QUIC pcap 파일 분석 시작 (64개 특징 추출)")
    print(f"OS: {platform.system()}")
    print(f"tshark: {TSHARK_CMD}")
    print(f"PCAP 루트 디렉토리: {PCAP_ROOT_DIR}")
    print(f"출력 디렉토리: {OUTPUT_DIR}")
    print("=" * 80)
    
    # 출력 디렉토리 구조 생성
    config.setup_output_directories()
    print("✓ 출력 폴더 구조 생성 완료")
    
    # 모든 폴더에서 모든 pcap 파일 찾기
    pcap_files = find_all_pcap_files(PCAP_ROOT_DIR)
    
    if not pcap_files:
        print("❌ 분석할 pcap 파일을 찾을 수 없습니다.")
        return
    
    print(f"✓ {len(pcap_files)}개의 pcap 파일 발견")
    for pcap_file in pcap_files:
        print(f"  - {pcap_file.relative_to(PCAP_ROOT_DIR)}")
    
    print("\n" + "=" * 80)
    print("분석 시작...")
    print("=" * 80 + "\n")
    
    # Dynamically initialize total_stats based on config
    total_stats = {key: 0 for key in config.DATASETS}
    
    for i, pcap_file in enumerate(pcap_files, 1):
        print(f"\n[{i}/{len(pcap_files)}] {pcap_file.name}")
        print("-" * 80)
        
        stats = analyze_pcap_file(pcap_file)
        
        # stats keys are strings ('full', '5', etc.)
        for key, value in stats.items():
            if key in total_stats:
                total_stats[key] += value
    
    print("\n" + "=" * 80)
    print("분석 완료!")
    print("=" * 80)
    print(f"\n처리된 Flow 통계:")
    print(f"  - 전체 (full): {total_stats.get('full', 0)} flows")
    for window in PACKET_WINDOWS:
        print(f"  - 첫 {window}개 패킷: {total_stats.get(str(window), 0)} flows")
    
    print(f"\n결과 저장 위치:")
    for window_name, folder in OUTPUT_FOLDERS.items():
        csv_count = len(list(folder.glob("*.csv")))
        print(f"  - {folder}: {csv_count}개 CSV 파일")
    
    print("\n✓ 모든 작업이 완료되었습니다!")


if __name__ == "__main__":
    main()
