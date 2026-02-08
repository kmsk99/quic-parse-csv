import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
import lightgbm as lgb
import xgboost as xgb
import warnings
from csv_to_md import convert_csv_to_md
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.inspection import permutation_importance
import shap

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Configuration
DATASET_ROOT = 'dataset'
OUTPUT_ROOT = 'prediction'
DATASETS = ['5', '10', '15', '20', 'full']
LEAKAGE_COLUMNS = ['source_file', 'file', 'flow_id', 'client_ip', 'server_ip', 'client_port', 'server_port']

# Ensure output directory exists
os.makedirs(OUTPUT_ROOT, exist_ok=True)

def get_models():
    """
    Returns a dictionary of models to train.
    """
    return {
        'SVM': LinearSVC(dual="auto", random_state=42),
        'KNN': KNeighborsClassifier(n_neighbors=5),
        'GBC': GradientBoostingClassifier(random_state=42),
        'DT': DecisionTreeClassifier(random_state=42),
        'RF': RandomForestClassifier(n_estimators=100, random_state=42),
        'LR': LogisticRegression(random_state=42, max_iter=1000),
        'NB': GaussianNB(),
        'MLP': MLPClassifier(hidden_layer_sizes=(128, 64, 32), activation='relu', solver='adam', random_state=42, max_iter=500),
        'LGBM': lgb.LGBMClassifier(random_state=42, verbose=-1),
        'XGB': xgb.XGBClassifier(random_state=42, use_label_encoder=False, eval_metric='mlogloss')
    }

def process_dataset(dataset_name):
    print(f"\n{'='*30}")
    print(f"Processing Dataset: {dataset_name}")
    print(f"{'='*30}")

    dataset_path = os.path.join(DATASET_ROOT, dataset_name)
    train_path = os.path.join(dataset_path, 'train.csv')
    test_path = os.path.join(dataset_path, 'test.csv')

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print(f"Skipping {dataset_name}: Train or Test file not found.")
        return

    # Load Data
    print("Loading data...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    # Preprocessing
    print("Preprocessing...")
    
    # Drop leakage columns
    X_train = train_df.drop(columns=LEAKAGE_COLUMNS + ['label'], errors='ignore')
    y_train = train_df['label']
    
    X_test = test_df.drop(columns=LEAKAGE_COLUMNS + ['label'], errors='ignore')
    y_test = test_df['label']

    # Handle separate vectorizers/encoders if there are object columns
    # For now, assuming all features are numeric except potentially label and leakage
    # Check for non-numeric columns in X
    non_numeric_cols = X_train.select_dtypes(include=['object']).columns
    if len(non_numeric_cols) > 0:
        print(f"Warning: {len(non_numeric_cols)} non-numeric feature columns found: {list(non_numeric_cols)}")
        # Simple One-Hot Encoding for categorical features if any exist (though usually QUIC stats are numeric)
        X_train = pd.get_dummies(X_train, columns=non_numeric_cols)
        X_test = pd.get_dummies(X_test, columns=non_numeric_cols)
        # Align columns
        X_train, X_test = X_train.align(X_test, join='left', axis=1, fill_value=0)

    # Fill NaNs
    X_train = X_train.fillna(0)
    X_test = X_test.fillna(0)

    # Encode Labels
    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)
    y_test_enc = le.transform(y_test)
    
    # Scale Features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save outputs for this dataset
    model_dir = os.path.join(OUTPUT_ROOT, dataset_name)
    os.makedirs(model_dir, exist_ok=True)
    
    # Save Scaler and LabelEncoder for future inference
    joblib.dump(scaler, os.path.join(model_dir, 'scaler.pkl'))
    joblib.dump(le, os.path.join(model_dir, 'label_encoder.pkl'))

    # Train Models
    models = get_models()
    results = []

    for name, model in models.items():
        print(f"\nTraining {name}...")
        try:
            # Train
            model.fit(X_train_scaled, y_train_enc)
            
            # Predict
            y_pred = model.predict(X_test_scaled)
            
            # Metrics
            acc = accuracy_score(y_test_enc, y_pred)
            f1 = f1_score(y_test_enc, y_pred, average='weighted')
            prec = precision_score(y_test_enc, y_pred, average='weighted')
            rec = recall_score(y_test_enc, y_pred, average='weighted')
            
            print(f"  Accuracy: {acc:.4f}")
            print(f"  F1 Score: {f1:.4f}")
            
            results.append({
                'Dataset': dataset_name,
                'Model': name,
                'Accuracy': acc,
                'F1_Score': f1,
                'Precision': prec,
                'Recall': rec
            })

            # Save Model
            model_path = os.path.join(model_dir, f'{name}.pkl')
            joblib.dump(model, model_path)

            # Feature Importance (Permutation Importance)
            print(f"  Calculating Feature Importance for {name}...")
            r = permutation_importance(model, X_test_scaled, y_test_enc,
                                       n_repeats=10,
                                       random_state=42,
                                       n_jobs=-1)
            
            # Create Feature Importance Plot
            sorted_idx = r.importances_mean.argsort()[::-1][:20]  # Top 20
            
            plt.figure(figsize=(10, 8))
            sns.barplot(x=r.importances_mean[sorted_idx], y=pd.Index(X_train.columns)[sorted_idx])
            plt.title(f'{name} Feature Importance (Permutation)')
            plt.xlabel('Importance Mean')
            plt.tight_layout()
            plt.savefig(os.path.join(model_dir, f'feature_importance_{name}.png'))
            plt.close()

            # SHAP Analysis
            print(f"  Calculating SHAP for {name}...")
            try:
                # Use TreeExplainer for tree models, Linear for others
                # Use modern explainer(X) API which returns an Explanation object
                if name in ['GBC', 'DT', 'RF', 'LGBM', 'XGB']:
                    explainer = shap.TreeExplainer(model)
                elif name in ['SVM', 'LR']:
                    # For Linear models, we need a background dataset (X_train)
                    # We use a summary (kmeans) to keep it fast, or just a sample
                    masker = shap.maskers.Independent(data=X_train_scaled) if len(X_train_scaled) < 100 else shap.maskers.Independent(data=shap.kmeans(X_train_scaled, 10))
                    explainer = shap.LinearExplainer(model, masker=masker)
                else:
                    print(f"  Skipping SHAP for {name} (Not fully supported for this plot type)")
                    explainer = None

                if explainer is not None:
                    # Calculate SHAP values (returns Explanation object)
                    # Limit to a sample if test set is huge to speed up
                    X_shap = X_test_scaled[:500] if len(X_test_scaled) > 500 else X_test_scaled
                    shap_values_obj = explainer(X_shap)
                    
                    # Handle shape (samples, features, classes) for multiclass/binary
                    # shap_values_obj.values is numpy array
                    # If binary (classes=2), usually shape is (N, M, 2) or (N, M) depending on model
                    # We want to plot for the prediction of the positive class (1)
                    
                    vals_to_plot = shap_values_obj
                    if len(shap_values_obj.shape) == 3:
                        # (Samples, Features, Classes) -> Select Class 1
                        vals_to_plot = shap_values_obj[:, :, 1]
                    
                    plt.figure()
                    # 'dot' is the default but let's be explicit, this is the "summary plot" user wants
                    shap.summary_plot(vals_to_plot, X_shap, feature_names=X_test.columns, show=False, plot_type='violin') # or dot
                    plt.title(f'{name} SHAP Summary')
                    plt.tight_layout()
                    plt.savefig(os.path.join(model_dir, f'shap_summary_{name}.png'))
                    plt.close()
                    
                    # Also save separate dot plot if they distinctly asked for "red/blue spread", which is 'dot'
                    plt.figure()
                    shap.summary_plot(vals_to_plot, X_shap, feature_names=X_test.columns, show=False, plot_type='dot')
                    plt.title(f'{name} SHAP Summary (Dot)')
                    plt.tight_layout()
                    plt.savefig(os.path.join(model_dir, f'shap_summary_dot_{name}.png'))
                    plt.close()

            except Exception as e:
                print(f"  SHAP calculation failed for {name}: {str(e)}")
            
        except Exception as e:
            print(f"  Error training {name}: {str(e)}")

    # Save Results CSV
    results_df = pd.DataFrame(results)
    results_path = os.path.join(model_dir, 'results.csv')
    results_df.to_csv(results_path, index=False)
    print(f"\nResults saved to {results_path}")
    
    # Convert to Markdown
    convert_csv_to_md(results_path)

def main():
    for dataset in DATASETS:
        process_dataset(dataset)

if __name__ == "__main__":
    main()
