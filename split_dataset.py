
#!/usr/bin/env python3
"""
merged 폴더의 각 CSV 파일을 독립적으로 train/test/valid로 분리하는 스크립트
- 각 파일별로 가장 적은 라벨의 개수를 각 라벨의 최댓값으로 설정
- 각 데이터셋에서 라벨 비율을 1:1:1:1로 유지
- random seed 사용 (config.RANDOM_SEED)
- dataset/{folder_name}/train.csv, test.csv, valid.csv 형태로 저장
"""

import pandas as pd
from pathlib import Path
import numpy as np
import re
import sys

# Configuration Import
import config

MERGED_DIR = config.MERGED_DIR
DATASET_DIR = config.DATASET_DIR
RANDOM_SEED = config.RANDOM_SEED
REQUIRED_LABELS = config.REQUIRED_LABELS


def get_folder_name_from_filename(filename):
    """파일명에서 폴더명을 추출합니다."""
    match = re.search(r'merged_(\w+)\.csv', filename)
    if match:
        return match.group(1)
    return "unknown"


def analyze_label_distribution(df):
    """라벨 분포를 분석하고 가장 적은 라벨의 개수를 반환합니다."""
    if 'label' not in df.columns:
        raise ValueError("'label' 컬럼이 없습니다.")
    
    # 라벨 정규화 (대소문자 통일)
    df['label_normalized'] = df['label'].str.upper()
    
    # 각 라벨의 개수 확인
    normalized_counts = df['label_normalized'].value_counts()
    
    # 가장 적은 라벨의 개수 찾기
    min_count = min([normalized_counts.get(label, 0) for label in REQUIRED_LABELS])
    
    return min_count, normalized_counts


def balance_and_split(df, max_count_per_label, labels):
    """데이터를 균형 맞추고 train/test/valid로 분리합니다."""
    np.random.seed(RANDOM_SEED)
    
    # train/test/valid로 분리 (70/15/15 비율)
    train_dfs = []
    test_dfs = []
    valid_dfs = []
    
    for label in labels:
        label_df = df[df['label_normalized'] == label].copy()
        
        if len(label_df) == 0:
            print(f"    ⚠️  Warning: No data found for label {label}")
            continue
        
        # 최대 개수만큼 랜덤 샘플링
        if len(label_df) > max_count_per_label:
            label_df = label_df.sample(n=max_count_per_label, random_state=RANDOM_SEED)
        
        # 인덱스 리셋
        label_df = label_df.reset_index(drop=True)
        
        # 70/15/15로 분리
        n_total = len(label_df)
        n_train = int(n_total * 0.7)
        n_test = int(n_total * 0.15)
        # 나머지는 valid
        
        # 셔플
        label_df = label_df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
        
        train_dfs.append(label_df.iloc[:n_train])
        test_dfs.append(label_df.iloc[n_train:n_train+n_test])
        valid_dfs.append(label_df.iloc[n_train+n_test:])
    
    # 각 데이터셋 합치기
    train_df = pd.concat(train_dfs, ignore_index=True).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    test_df = pd.concat(test_dfs, ignore_index=True).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    valid_df = pd.concat(valid_dfs, ignore_index=True).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    
    # label_normalized 컬럼 제거
    for df in [train_df, test_df, valid_df]:
        if 'label_normalized' in df.columns:
            df.drop(columns=['label_normalized'], inplace=True)
    
    return train_df, test_df, valid_df


def process_single_file(csv_file):
    """단일 CSV 파일을 처리하여 train/test/valid로 분리합니다."""
    filename = csv_file.name
    folder_name = get_folder_name_from_filename(filename)
    
    print(f"\n{'=' * 80}")
    print(f"Processing: {filename} -> dataset/{folder_name}/")
    print(f"{'=' * 80}")
    
    # CSV 파일 로드
    print(f"\nLoading {filename}...")
    df = pd.read_csv(csv_file)
    print(f"  Loaded {len(df):,} rows")
    
    # 라벨 분포 분석
    print(f"\nAnalyzing label distribution...")
    label_counts = df['label'].value_counts()
    print("  Original Label Distribution:")
    for label, count in label_counts.items():
        print(f"    {label}: {count:,} rows")
    
    # 라벨 정규화
    df['label_normalized'] = df['label'].str.upper()
    
    # 각 라벨의 개수 확인
    normalized_counts = df['label_normalized'].value_counts()
    print("\n  Normalized Label Distribution:")
    for label in REQUIRED_LABELS:
        count = normalized_counts.get(label, 0)
        print(f"    {label}: {count:,} rows")
    
    # 가장 적은 라벨의 개수 찾기
    min_count = min([normalized_counts.get(label, 0) for label in REQUIRED_LABELS])
    
    if min_count == 0:
        print(f"  ⚠️  Warning: Some labels have 0 count. Skipping this file.")
        return
    
    print(f"\n  Minimum label count: {min_count:,}")
    print(f"  This will be the maximum count for each label in the balanced dataset.")
    
    # 균형 맞추고 분리
    print(f"\nBalancing and splitting dataset...")
    train_df, test_df, valid_df = balance_and_split(df, min_count, REQUIRED_LABELS)
    
    # 결과 출력
    print(f"\n  Balanced Dataset Split:")
    print(f"    Train: {len(train_df):,} rows")
    print(f"      {train_df['label'].value_counts().sort_index().to_dict()}")
    print(f"    Test: {len(test_df):,} rows")
    print(f"      {test_df['label'].value_counts().sort_index().to_dict()}")
    print(f"    Valid: {len(valid_df):,} rows")
    print(f"      {valid_df['label'].value_counts().sort_index().to_dict()}")
    
    # 저장
    output_dir = DATASET_DIR / folder_name
    output_dir.mkdir(parents=True, exist_ok=True)
    
    train_path = output_dir / "train.csv"
    test_path = output_dir / "test.csv"
    valid_path = output_dir / "valid.csv"
    
    train_df.to_csv(train_path, index=False)
    print(f"\n  ✓ Saved: {train_path}")
    
    test_df.to_csv(test_path, index=False)
    print(f"  ✓ Saved: {test_path}")
    
    valid_df.to_csv(valid_path, index=False)
    print(f"  ✓ Saved: {valid_path}")


def main():
    """메인 함수"""
    print("=" * 80)
    print("Dataset Split Script")
    print("=" * 80)
    
    DATASET_DIR.mkdir(exist_ok=True)
    
    csv_files = sorted(MERGED_DIR.glob("*.csv"))
    
    if not csv_files:
        print(f"⚠️ {MERGED_DIR} 폴더에 CSV 파일이 없습니다.")
        return
    
    print(f"\nFound {len(csv_files)} CSV files:")
    for f in csv_files:
        print(f"  - {f.name}")
    
    for csv_file in csv_files:
        try:
            process_single_file(csv_file)
        except Exception as e:
            print(f"\n  ❌ Error processing {csv_file.name}: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    print("\n" + "=" * 80)
    print("✓ All datasets split completed!")
    print("=" * 80)
    print(f"\nAll datasets saved to {DATASET_DIR}/")


if __name__ == "__main__":
    main()
