import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, cross_validate
from sklearn.metrics import make_scorer, f1_score, accuracy_score

def run_10fold_group_cv(file_path):
    df = pd.read_csv(file_path)
    
    # 1. 제외할 피처 리스트 (미래 정보 및 식별자 제거)
    drop_cols = [
        'label', 'file', 'source_file', 'flow_id', 
        'client_ip', 'server_ip', 'client_port', 'server_port',
        'total_packets_in_flow', 'total_bytes_in_flow', 'flow_duration', 
        'end_time', 'start_time', 'packets_after_n', 'bytes_after_n',
        'mean_packet_size_over_flow', 'total_ack_count', 'window_size'
    ]
    
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    y = df['label']
    groups = df['file']  # 파일 단위로 그룹핑

    # 2. 모델 및 교차 검증 설정 (GroupKFold 사용)
    model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    group_kfold = GroupKFold(n_splits=10)

    # 3. 교차 검증 수행 (정확도와 F1-score 측정)
    print(f"\n[10-Fold 교차 검증 시작: {file_path}]")
    scoring = {
        'accuracy': 'accuracy',
        'f1_macro': 'f1_macro'
    }
    
    cv_results = cross_validate(model, X, y, groups=groups, cv=group_kfold, scoring=scoring)

    # 4. 최종 결과 출력
    print(f"--- 최종 평균 성능 (10 Folds Average) ---")
    print(f"평균 Accuracy: {cv_results['test_accuracy'].mean():.4f} (±{cv_results['test_accuracy'].std():.4f})")
    print(f"평균 F1-Score (Macro): {cv_results['test_f1_macro'].mean():.4f} (±{cv_results['test_f1_macro'].std():.4f})")

# N=6, 7, 8, 9 파일들에 대해 실행
import glob
import os
path = r'C:\quic-parse-csv\merged'
for n in [5, 10, 15, 20]:
    file = os.path.join(path, f"merged_{n}.csv")
    if os.path.exists(file):
        run_10fold_group_cv(file)