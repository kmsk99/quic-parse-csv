import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# 1. 데이터 입력 (실행 결과에서 추출한 수치)
data = {
    'N': [5, 10, 15, 20, 30],  # Full은 편의상 30으로 표시
    'NORMAL': [1.00, 1.00, 1.00, 1.00, 1.00],
    'CONNECTION_FLOOD': [1.00, 1.00, 1.00, 1.00, 1.00],
    'GET_FLOOD': [0.48, 0.96, 0.97, 0.96, 0.97],
    'SCAN': [0.96, 0.99, 0.99, 0.99, 1.00]
}

df = pd.DataFrame(data)
df_melted = df.melt(id_vars='N', var_name='Traffic Class', value_name='F1-Score')

# 2. 그래프 스타일 설정
plt.figure(figsize=(10, 6))
sns.set_style("whitegrid")
sns.lineplot(data=df_melted, x='N', y='F1-Score', hue='Traffic Class', 
             marker='o', markersize=8, linewidth=2.5)

# 3. 그래프 상세 설정 (논문용 스타일)
plt.title('QUIC Traffic Classification Performance by Packet Window (N)', fontsize=15, pad=15)
plt.xlabel('Number of Packets (N)', fontsize=12)
plt.ylabel('F1-Score', fontsize=12)
plt.xticks([5, 10, 15, 20, 30], ['N=5', 'N=10', 'N=15', 'N=20', 'Full'])
plt.ylim(0.4, 1.05)
plt.legend(title='Traffic Class', loc='lower right', frameon=True)

# 강조 표시 (N=10 지점)
plt.axvline(x=10, color='red', linestyle='--', alpha=0.5)
plt.text(10.5, 0.7, 'Optimal Detection Point\n(N=10)', color='red', fontweight='bold')

plt.tight_layout()

# 4. 이미지 저장
plt.savefig('quic_performance_plot.png', dpi=300)
print("그래프 저장이 완료되었습니다: quic_performance_plot.png")
plt.show()