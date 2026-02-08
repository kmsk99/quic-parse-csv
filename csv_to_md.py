import pandas as pd
import os
import sys

def convert_csv_to_md(csv_path):
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        return

    try:
        df = pd.read_csv(csv_path)
        
        # Sort by Accuracy descending
        if 'Accuracy' in df.columns:
            df = df.sort_values(by='Accuracy', ascending=False)

        md_path = csv_path.replace('.csv', '.md')
        
        with open(md_path, 'w') as f:
            f.write(f"# Model Evalutation Results\n\n")
            f.write(df.to_markdown(index=False))
        
        print(f"Successfully created Markdown report: {md_path}")
        
    except Exception as e:
        print(f"Error converting CSV to MD: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        convert_csv_to_md(sys.argv[1])
    else:
        print("Usage: python csv_to_md.py <path_to_csv>")
