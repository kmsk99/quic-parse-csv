#제외할 feature#

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def analyze_model_quality(file_path):
    df = pd.read_csv(file_path)
    
    # 1. 학습에서 완전히 제외할 '미래 정보' 및 '식별 정보' 리스트
    drop_cols = [
    # 식별 정보 및 메타데이터 (모델 학습에 부적합)
    'label', 
    'source_file', 
    'file', 
    'flow_id', 
    'client_ip', 
    'server_ip', 
    'client_port', 
    'server_port',
    
    # 시간 관련 정보 및 미래 정보 (Feature Leakage 방지)
    'start_time',
    'end_time',
    'duration',
    'flow_duration',
    
    # Flow 전체 통계 정보 (학습 시점에 알 수 없는 사후 데이터)
    'total_packets_in_flow', 
    'total_bytes_in_flow', 
    'mean_packet_size_over_flow', 
    'total_ack_count',
    'packets_after_n', 
    'bytes_after_n',
    
    # 중복되거나 과적합 우려가 있는 네트워크 통계치
    'total_packets', 
    'total_bytes', 
    'outgoing_bytes', 
    'incoming_bytes',
    
    # 기타 프로토콜 특정 및 비중 관련 지표
    'window_size',
    'spin_bit_count', 
    'spin_bit_ratio', 
    'no_spin_bit_ratio'
]
    
    # 데이터프레임에 존재하는 컬럼만 골라서 제거
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    
    # 2. 모델 학습 (클래스 불균형 가중치 부여)
    model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    model.fit(X_train, y_train)
    
    # 3. 중요도 상위 5개 출력
    importances = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
    print(f"\n[N={file_path.split('_')[-1]}] Top 5 Features:")
    print(importances.head(5))
    
    # 4. 분류 성능 보고서 (불균형 데이터 대응 확인)
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

# 실행 (모든 merged 파일에 대해 수행)
import glob
import os

path = r'C:\quic-parse-csv\merged'
all_files = glob.glob(os.path.join(path, "merged_*.csv"))

for file in all_files:
    try:
        analyze_model_quality(file)
    except Exception as e:
        with open("check3_error.txt", "a") as f:
            f.write(f"Error processing {file}: {e}\n")
        print(f"Error processing {file}")