import pandas as pd
import glob
import os
import seaborn as sns
import matplotlib.pyplot as plt

# 1. 데이터 로드 (사용자 경로 지정)
path = r'C:\quic-parse-csv\merged'
all_files = glob.glob(os.path.join(path, "merged_*.csv"))

def validate_quic_data(file_list):
    for file in file_list:
        n_value = file.split('_')[-1].split('.')[0]
        df = pd.read_csv(file)
        
        print(f"\n{'='*20} 분석 보고서: N={n_value} {'='*20}")
        
        # [검증 1] 클래스 불균형 체크 (Class Imbalance)
        # CSV에 'label' 혹은 공격 타입을 구분하는 컬럼이 있어야 합니다. 
        # (없을 경우 파일명 등으로 수동 추가 필요)
        if 'label' in df.columns:
            print(f"- 클래스 분포:\n{df['label'].value_counts(normalize=True)}")
        
        # [검증 2] Zero Variance 피처 (정보가 없는 피처 제거용)
        constant_cols = df.columns[df.nunique() <= 1].tolist()
        print(f"- 무의미한 피처(상수값): {len(constant_cols)}개 발견")
        
        # [검증 3] 공격별 주요 피처 변별력 시각화 (Boxplot)
        # 리뷰어에게 보여줄 '근거'가 됩니다.
        key_features = ['initial_ratio', 'iat_mean', 'packet_size_mean']
        available_keys = [f for f in key_features if f in df.columns]
        
        if 'label' in df.columns and available_keys:
            fig, axes = plt.subplots(1, len(available_keys), figsize=(15, 5))
            for i, feat in enumerate(available_keys):
                sns.boxplot(x='label', y=feat, data=df, ax=axes[i])
                axes[i].set_title(f'N={n_value}: {feat}')
            plt.tight_layout()
            output_file = f'analysis_N={n_value}.png'
            plt.savefig(output_file)
            print(f"- 그래프 저장 완료: {output_file}")
            plt.close()

# 실행
validate_quic_data(all_files)