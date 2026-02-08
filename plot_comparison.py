import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuration
RESULTS_DIR = 'prediction'
OUTPUT_DIR = 'prediction/comparison'
DATASETS = ['5', '10', '15', '20', 'full']

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data():
    all_results = []
    for dataset in DATASETS:
        result_path = os.path.join(RESULTS_DIR, dataset, 'results.csv')
        if os.path.exists(result_path):
            df = pd.read_csv(result_path)
            # Map 'full' to a numeric value for plotting if needed, 
            # but usually better to treat as categorical or handle specially.
            # For this plot, let's keep it categorical on the x-axis but ordered.
            df['Packet_Count'] = dataset
            all_results.append(df)
        else:
            print(f"Warning: Results for {dataset} not found at {result_path}")
    
    if not all_results:
        return pd.DataFrame()
    
    return pd.concat(all_results, ignore_index=True)

def plot_metric(df, metric, title, filename):
    plt.figure(figsize=(12, 8))
    sns.set_style("whitegrid")
    
    # Create the plot
    sns.lineplot(data=df, x='Packet_Count', y=metric, hue='Model', marker='o', linewidth=2.5)
    
    plt.title(title, fontsize=16)
    plt.xlabel('Number of Initial Packets', fontsize=14)
    plt.ylabel(metric, fontsize=14)
    plt.legend(title='Model', bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    # Save
    save_path = os.path.join(OUTPUT_DIR, filename)
    plt.savefig(save_path, dpi=300)
    print(f"Saved plot to {save_path}")
    plt.close()

def main():
    print("Loading results...")
    df = load_data()
    
    if df.empty:
        print("No results found to plot.")
        return

    # Ensure Packet_Count order
    df['Packet_Count'] = pd.Categorical(df['Packet_Count'], categories=DATASETS, ordered=True)

    print("Generating plots...")
    plot_metric(df, 'Accuracy', 'Model Accuracy vs. Packet Count', 'accuracy_comparison.png')
    plot_metric(df, 'F1_Score', 'Model F1 Score vs. Packet Count', 'f1_score_comparison.png')
    
    print("Done.")

if __name__ == "__main__":
    main()
