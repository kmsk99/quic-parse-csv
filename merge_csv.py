#!/usr/bin/env python3
"""
output 폴더의 모든 CSV 파일을 합치고 label을 추가하는 스크립트
"""

import pandas as pd
from pathlib import Path
from typing import List
import os

OUTPUT_DIR = Path("output")
MERGED_DIR = Path("merged")

# 폴더별 출력 파일명
OUTPUT_FILES = {
    'full': 'merged_full.csv',
    5: 'merged_5.csv',
    10: 'merged_10.csv',
    15: 'merged_15.csv',
    20: 'merged_20.csv',
}


def get_label_from_filename(filename: str) -> str:
    """
    파일명에서 label을 추출합니다.
    
    Args:
        filename: 파일명 (예: "QUIC_CONNECT1.csv", "SCAN_HTTP3.csv")
        
    Returns:
        label: "quic", "scan", "http", 또는 "normal"
    """
    filename_lower = filename.lower()
    
    if 'quic_connect' in filename_lower or 'quicconnect' in filename_lower:
        return 'quic'
    elif 'scan' in filename_lower:
        return 'scan'
    elif 'http' in filename_lower:
        return 'http'
    else:
        return 'normal'


def merge_csv_files(folder_path: Path, output_file: Path) -> int:
    """
    폴더 내의 모든 CSV 파일을 합칩니다.
    
    Args:
        folder_path: CSV 파일들이 있는 폴더 경로
        output_file: 출력 파일 경로
        
    Returns:
        처리된 파일 개수
    """
    csv_files = sorted(folder_path.glob("*.csv"))
    
    if not csv_files:
        print(f"  ⚠️  {folder_path.name}: CSV 파일 없음")
        return 0
    
    all_dataframes = []
    
    for csv_file in csv_files:
        try:
            # CSV 파일 읽기
            df = pd.read_csv(csv_file)
            
            # 파일명에서 label 추출
            label = get_label_from_filename(csv_file.name)
            
            # label 컬럼 추가
            df['label'] = label
            
            # 원본 파일명도 추가 (디버깅용)
            df['source_file'] = csv_file.name
            
            all_dataframes.append(df)
            
        except Exception as e:
            print(f"  ❌ {csv_file.name} 읽기 오류: {e}")
            continue
    
    if not all_dataframes:
        print(f"  ⚠️  {folder_path.name}: 유효한 데이터 없음")
        return 0
    
    # 모든 데이터프레임 합치기
    merged_df = pd.concat(all_dataframes, ignore_index=True)
    
    # label 컬럼을 앞쪽으로 이동
    cols = ['label', 'source_file'] + [c for c in merged_df.columns if c not in ['label', 'source_file']]
    merged_df = merged_df[cols]
    
    # 저장
    merged_df.to_csv(output_file, index=False)
    
    print(f"  ✓ {folder_path.name}: {len(csv_files)}개 파일 → {len(merged_df)}개 행")
    
    return len(csv_files)


def main():
    """메인 함수"""
    print("=" * 80)
    print("CSV 파일 병합 및 Label 추가")
    print("=" * 80)
    
    # merged 디렉토리 생성
    MERGED_DIR.mkdir(exist_ok=True)
    
    # 각 폴더별로 처리
    total_files = 0
    
    for folder_name, output_filename in OUTPUT_FILES.items():
        folder_path = OUTPUT_DIR / str(folder_name)
        output_path = MERGED_DIR / output_filename
        
        if not folder_path.exists():
            print(f"  ⚠️  {folder_path} 폴더가 존재하지 않습니다.")
            continue
        
        print(f"\n[{folder_name}] 처리 중...")
        file_count = merge_csv_files(folder_path, output_path)
        total_files += file_count
    
    # 요약 출력
    print("\n" + "=" * 80)
    print("병합 완료!")
    print("=" * 80)
    print(f"\n총 {total_files}개 파일 처리")
    print(f"\n결과 파일:")
    for folder_name, output_filename in OUTPUT_FILES.items():
        output_path = MERGED_DIR / output_filename
        if output_path.exists():
            df = pd.read_csv(output_path)
            print(f"  - {output_filename}: {len(df)}개 행")
            # Label 분포 출력
            if 'label' in df.columns:
                label_counts = df['label'].value_counts()
                print(f"    Label 분포: {dict(label_counts)}")
    
    print(f"\n✓ 모든 파일이 {MERGED_DIR} 폴더에 저장되었습니다!")


if __name__ == "__main__":
    main()
