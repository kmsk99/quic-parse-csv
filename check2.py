import pandas as pd
import numpy as np
from scipy import stats
from sklearn.ensemble import RandomForestClassifier

def verify_thesis_data(file_path):
    df = pd.read_csv(file_path)
    # label 컬럼이 있다고 가정 (NORMAL, SCAN 등)
    label_col = 'label' 
    
    print(f"\n[데이터 검증 보고서: {file_path}]")
    
    # 1. 클래스 불균형 확인 (재현성 관점)
    counts = df[label_col].value_counts()
    print(f"- 클래스 분포:\n{counts}")
    
    # 2. 통계적 유의성 검정 (리뷰어 설득용)
    # 'initial_ratio'가 클래스별로 정말 다른지 검정
    groups = [group[1]['initial_ratio'] for group in df.groupby(label_col)]
    h_stat, p_val = stats.kruskal(*groups)
    print(f"- initial_ratio의 통계적 유의성 (p-value): {p_val:.5f}")
    if p_val < 0.05:
        print("  => 결과: 클래스 간 차이가 통계적으로 매우 유의함 (합격)")

    # 3. 피처 중요도 분석 (어떤 피처가 논문의 핵심인가?)
    X = df.drop([label_col, 'file', 'flow_id'], axis=1, errors='ignore')
    X = X.select_dtypes(include=[np.number]).fillna(0)
    y = df[label_col]
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X, y)
    
    importances = pd.Series(rf.feature_importances_, index=X.columns)
    print("- 상위 5개 중요 피처:")
    print(importances.sort_values(ascending=False).head(5))

# 실행 (모든 merged 파일에 대해 수행)
import glob
import os

path = r'C:\quic-parse-csv\merged'
all_files = glob.glob(os.path.join(path, "merged_*.csv"))

for file in all_files:
    verify_thesis_data(file)