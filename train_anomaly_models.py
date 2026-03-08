#!/usr/bin/env python3
"""
Train and evaluate anomaly detectors on merged QUIC datasets.

Design:
- Train on NORMAL-only flows
- Split by source_file to avoid mixing flows from the same capture
- Evaluate separate roles for early (window 5) and final (full flow)
- Save metrics, plots, and selected thresholds under prediction/anomaly/
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.base import clone
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

import config


RANDOM_SEED = config.RANDOM_SEED
MERGED_DIR = config.MERGED_DIR
OUTPUT_ROOT = config.MODEL_DIR / "anomaly"
OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

EXCLUDED_FEATURES = {
    "label",
    "source_file",
    "file",
    "flow_id",
    "client_ip",
    "server_ip",
    "client_port",
    "server_port",
    "window_size",
}

EARLY_MAX_NORMAL_FPR = 0.10
FINAL_MAX_NORMAL_FPR = 0.05
THRESHOLD_GRID_SIZE = 400
MODEL_ORDER = ["LOF", "IsolationForest", "OneClassSVM"]
PALETTE = {"NORMAL": "#4E79A7", "ABNORMAL": "#E15759"}
ATTACK_ORDER = ["GET_FLOOD", "CONNECTION_FLOOD", "SCAN"]


@dataclass(frozen=True)
class StageConfig:
    dataset_name: str
    title: str
    objective: str
    max_normal_fpr: float


STAGES = [
    StageConfig(
        dataset_name="5",
        title="Early Warning (5 packets)",
        objective="early",
        max_normal_fpr=EARLY_MAX_NORMAL_FPR,
    ),
    StageConfig(
        dataset_name="full",
        title="Final Confirmation (full flow)",
        objective="final",
        max_normal_fpr=FINAL_MAX_NORMAL_FPR,
    ),
]


def get_models(train_rows: int) -> dict[str, object]:
    lof_neighbors = max(5, min(35, train_rows - 1))
    return {
        "LOF": LocalOutlierFactor(n_neighbors=lof_neighbors, novelty=True),
        "IsolationForest": IsolationForest(
            n_estimators=300,
            contamination="auto",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        ),
        "OneClassSVM": OneClassSVM(kernel="rbf", nu=0.05, gamma="scale"),
    }


def build_source_file_split() -> pd.DataFrame:
    reference = pd.read_csv(MERGED_DIR / "merged_full.csv", usecols=["label", "source_file"])
    grouped = (
        reference.drop_duplicates()
        .groupby("label")["source_file"]
        .apply(lambda series: sorted(series.unique()))
    )

    rng = np.random.default_rng(RANDOM_SEED)
    rows: list[dict[str, str]] = []

    for label, source_files in grouped.items():
        shuffled = list(source_files)
        rng.shuffle(shuffled)
        count = len(shuffled)

        if label == "NORMAL":
            train_count = max(1, int(round(count * 0.70)))
            valid_count = max(1, int(round(count * 0.15)))
            if train_count + valid_count >= count:
                valid_count = max(1, count - train_count - 1)
            test_count = count - train_count - valid_count
            if test_count <= 0:
                test_count = 1
                if valid_count > 1:
                    valid_count -= 1
                else:
                    train_count -= 1

            assignments = (
                [("train", name) for name in shuffled[:train_count]]
                + [("valid", name) for name in shuffled[train_count : train_count + valid_count]]
                + [("test", name) for name in shuffled[train_count + valid_count :]]
            )
        else:
            valid_count = max(1, count // 2)
            assignments = (
                [("valid", name) for name in shuffled[:valid_count]]
                + [("test", name) for name in shuffled[valid_count:]]
            )

        for split_name, source_file in assignments:
            rows.append({"label": label, "source_file": source_file, "split": split_name})

    split_df = pd.DataFrame(rows).sort_values(["label", "split", "source_file"]).reset_index(drop=True)
    split_df.to_csv(OUTPUT_ROOT / "source_file_split.csv", index=False)
    return split_df


def load_stage_dataframe(dataset_name: str, split_df: pd.DataFrame) -> pd.DataFrame:
    data_path = MERGED_DIR / f"merged_{dataset_name}.csv"
    df = pd.read_csv(data_path)
    df = df.merge(split_df, on=["label", "source_file"], how="inner").copy()
    return df.assign(is_anomaly=(df["label"] != "NORMAL").astype(int))


def get_feature_columns(df: pd.DataFrame) -> list[str]:
    return [
        column
        for column in df.columns
        if column not in EXCLUDED_FEATURES | {"split", "is_anomaly"}
        and pd.api.types.is_numeric_dtype(df[column])
    ]


def split_by_partition(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    train_df = df[(df["split"] == "train") & (df["label"] == "NORMAL")].copy()
    valid_df = df[df["split"] == "valid"].copy()
    test_df = df[df["split"] == "test"].copy()
    return train_df, valid_df, test_df


def fit_scaler(
    train_df: pd.DataFrame, valid_df: pd.DataFrame, test_df: pd.DataFrame, feature_columns: list[str]
) -> tuple[StandardScaler, np.ndarray, np.ndarray, np.ndarray]:
    scaler = StandardScaler()
    x_train = scaler.fit_transform(train_df[feature_columns].fillna(0.0))
    x_valid = scaler.transform(valid_df[feature_columns].fillna(0.0))
    x_test = scaler.transform(test_df[feature_columns].fillna(0.0))
    return scaler, x_train, x_valid, x_test


def anomaly_scores(model: object, x: np.ndarray) -> np.ndarray:
    if hasattr(model, "score_samples"):
        return -model.score_samples(x)
    return -model.decision_function(x)


def evaluate_at_threshold(y_true: np.ndarray, scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict[str, float]:
    predictions = (scores >= threshold).astype(int)
    normal_mask = labels == "NORMAL"
    anomaly_mask = ~normal_mask
    metrics = {
        "threshold": float(threshold),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "normal_fpr": float(predictions[normal_mask].mean()) if normal_mask.any() else np.nan,
        "anomaly_recall": float(predictions[anomaly_mask].mean()) if anomaly_mask.any() else np.nan,
    }

    for attack_label in ATTACK_ORDER:
        attack_mask = labels == attack_label
        if attack_mask.any():
            metrics[f"recall_{attack_label.lower()}"] = float(predictions[attack_mask].mean())
        else:
            metrics[f"recall_{attack_label.lower()}"] = np.nan

    return metrics


def select_threshold(
    stage: StageConfig, y_valid: np.ndarray, scores_valid: np.ndarray, labels_valid: np.ndarray
) -> dict[str, float]:
    normal_scores = scores_valid[labels_valid == "NORMAL"]
    candidate_thresholds = np.unique(
        np.quantile(normal_scores, np.linspace(0.50, 0.999, THRESHOLD_GRID_SIZE))
    )

    best_payload: dict[str, float] | None = None
    best_key: tuple[float, float, float] | None = None

    for threshold in candidate_thresholds:
        metrics = evaluate_at_threshold(y_valid, scores_valid, labels_valid, float(threshold))
        if metrics["normal_fpr"] > stage.max_normal_fpr:
            continue

        if stage.objective == "early":
            key = (
                metrics["anomaly_recall"],
                metrics["precision"],
                -metrics["normal_fpr"],
            )
        else:
            key = (
                metrics["f1"],
                metrics["precision"],
                -metrics["normal_fpr"],
            )

        if best_key is None or key > best_key:
            best_key = key
            best_payload = metrics

    if best_payload is None:
        fallback_threshold = float(np.quantile(normal_scores, 1.0 - stage.max_normal_fpr))
        best_payload = evaluate_at_threshold(y_valid, scores_valid, labels_valid, fallback_threshold)

    return best_payload


def rank_models(
    results_df: pd.DataFrame, stage: StageConfig, split_name: str = "test"
) -> pd.DataFrame:
    subset = results_df[(results_df["dataset"] == stage.dataset_name) & (results_df["split"] == split_name)].copy()
    if stage.objective == "early":
        subset = subset.sort_values(
            ["anomaly_recall", "recall_get_flood", "precision", "normal_fpr"],
            ascending=[False, False, False, True],
        )
    else:
        subset = subset.sort_values(
            ["f1", "precision", "recall", "normal_fpr"],
            ascending=[False, False, False, True],
        )
    return subset.reset_index(drop=True)


def plot_curve_comparison(curve_df: pd.DataFrame, x: str, y: str, title: str, output_path: Path) -> None:
    plt.figure(figsize=(8, 6))
    for model_name in MODEL_ORDER:
        model_df = curve_df[curve_df["model"] == model_name]
        if model_df.empty:
            continue
        plt.plot(model_df[x], model_df[y], linewidth=2, label=model_name)

    if x == "fpr":
        plt.plot([0, 1], [0, 1], linestyle="--", linewidth=1, color="#888888")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
    else:
        plt.xlabel("Recall")
        plt.ylabel("Precision")

    plt.title(title)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def plot_score_distribution(stage: StageConfig, scores_df: pd.DataFrame, model_name: str, threshold: float, output_path: Path) -> None:
    subset = scores_df[(scores_df["dataset"] == stage.dataset_name) & (scores_df["split"] == "test")].copy()
    subset["group"] = np.where(subset["label"] == "NORMAL", "NORMAL", "ABNORMAL")

    plt.figure(figsize=(9, 6))
    for group_name in ["NORMAL", "ABNORMAL"]:
        group_df = subset[subset["group"] == group_name]
        if group_df.empty:
            continue
        sns.kdeplot(
            group_df[model_name],
            fill=True,
            alpha=0.35,
            linewidth=2,
            label=group_name,
            color=PALETTE[group_name],
        )

    plt.axvline(threshold, linestyle="--", color="#222222", linewidth=2, label="Threshold")
    plt.xlabel("Anomaly Score")
    plt.ylabel("Density")
    plt.title(f"{stage.title}: Test Score Distribution ({model_name})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def plot_attack_recall(stage: StageConfig, test_results: pd.DataFrame, output_path: Path) -> None:
    chart_df = (
        test_results[test_results["dataset"] == stage.dataset_name][
            ["model", "recall_get_flood", "recall_connection_flood", "recall_scan"]
        ]
        .melt(id_vars="model", var_name="attack", value_name="recall")
        .assign(
            attack=lambda df: df["attack"]
            .str.replace("recall_", "", regex=False)
            .str.upper()
            .str.replace("_", " ", regex=False)
        )
    )

    plt.figure(figsize=(9, 6))
    sns.barplot(data=chart_df, x="attack", y="recall", hue="model", hue_order=MODEL_ORDER)
    plt.ylim(0, 1.05)
    plt.ylabel("Recall")
    plt.xlabel("")
    plt.title(f"{stage.title}: Test Recall by Attack Type")
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def plot_stage_policy(stage_policy_df: pd.DataFrame, output_path: Path) -> None:
    plt.figure(figsize=(9, 6))
    sns.barplot(data=stage_policy_df, x="label", y="flag_rate", hue="stage")
    plt.ylim(0, 1.05)
    plt.xlabel("")
    plt.ylabel("Positive Rate")
    plt.title("Two-Stage Policy on Common Test Flows")
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def run_stage(stage: StageConfig, split_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    print(f"\n{'=' * 80}")
    print(f"Stage: {stage.title}")
    print(f"{'=' * 80}")

    df = load_stage_dataframe(stage.dataset_name, split_df)
    feature_columns = get_feature_columns(df)
    train_df, valid_df, test_df = split_by_partition(df)
    scaler, x_train, x_valid, x_test = fit_scaler(train_df, valid_df, test_df, feature_columns)

    stage_dir = OUTPUT_ROOT / stage.dataset_name
    stage_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, stage_dir / "scaler.pkl")

    print(f"Rows: train={len(train_df):,} valid={len(valid_df):,} test={len(test_df):,}")
    print(f"Features: {len(feature_columns)}")
    print(f"Train normals: {len(train_df):,}")

    y_valid = valid_df["is_anomaly"].to_numpy()
    y_test = test_df["is_anomaly"].to_numpy()
    labels_valid = valid_df["label"].to_numpy()
    labels_test = test_df["label"].to_numpy()

    results_rows: list[dict[str, float | str]] = []
    curve_rows: list[dict[str, float | str]] = []
    score_rows: list[pd.DataFrame] = []

    models = get_models(len(train_df))

    for model_name, model in models.items():
        print(f"Training {model_name}...")
        fitted_model = clone(model)
        fitted_model.fit(x_train)

        model_dir = stage_dir / model_name
        model_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(fitted_model, model_dir / "model.pkl")

        train_scores = anomaly_scores(fitted_model, x_train)
        valid_scores = anomaly_scores(fitted_model, x_valid)
        test_scores = anomaly_scores(fitted_model, x_test)

        threshold_payload = select_threshold(stage, y_valid, valid_scores, labels_valid)
        threshold = threshold_payload["threshold"]

        for split_name, y_true, labels, scores in [
            ("valid", y_valid, labels_valid, valid_scores),
            ("test", y_test, labels_test, test_scores),
        ]:
            threshold_metrics = evaluate_at_threshold(y_true, scores, labels, threshold)
            row: dict[str, float | str] = {
                "dataset": stage.dataset_name,
                "stage": stage.title,
                "objective": stage.objective,
                "model": model_name,
                "split": split_name,
                "threshold": threshold,
                "selected_on_valid": split_name == "test",
                "roc_auc": float(roc_auc_score(y_true, scores)),
                "pr_auc": float(average_precision_score(y_true, scores)),
            }
            row.update(threshold_metrics)
            results_rows.append(row)

        model_scores_df = pd.DataFrame(
            {
                "dataset": stage.dataset_name,
                "stage": stage.title,
                "split": "test",
                "source_file": test_df["source_file"].to_numpy(),
                "flow_id": test_df["flow_id"].to_numpy(),
                "label": labels_test,
                model_name: test_scores,
            }
        )
        score_rows.append(model_scores_df)

        fpr, tpr, _ = roc_curve(y_test, test_scores)
        precision_curve, recall_curve, _ = precision_recall_curve(y_test, test_scores)
        curve_rows.extend(
            {"dataset": stage.dataset_name, "model": model_name, "curve": "roc", "fpr": x, "tpr": y}
            for x, y in zip(fpr, tpr)
        )
        curve_rows.extend(
            {
                "dataset": stage.dataset_name,
                "model": model_name,
                "curve": "pr",
                "recall_curve": x,
                "precision_curve": y,
            }
            for x, y in zip(recall_curve, precision_curve)
        )

        with open(model_dir / "threshold.json", "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "dataset": stage.dataset_name,
                    "stage": stage.title,
                    "objective": stage.objective,
                    "max_normal_fpr": stage.max_normal_fpr,
                    "threshold": threshold,
                    "valid_metrics": threshold_payload,
                },
                handle,
                indent=2,
            )

    results_df = pd.DataFrame(results_rows)
    curve_df = pd.DataFrame(curve_rows)
    score_df = score_rows[0]
    for model_scores_df in score_rows[1:]:
        score_df = score_df.merge(
            model_scores_df,
            on=["dataset", "stage", "split", "source_file", "flow_id", "label"],
            how="inner",
        )

    results_df.to_csv(stage_dir / "metrics.csv", index=False)
    curve_df.to_csv(stage_dir / "curves.csv", index=False)
    score_df.to_csv(stage_dir / "test_scores.csv", index=False)

    plot_curve_comparison(
        curve_df[curve_df["curve"] == "roc"],
        x="fpr",
        y="tpr",
        title=f"{stage.title}: ROC Curve",
        output_path=stage_dir / "roc_curve.png",
    )
    plot_curve_comparison(
        curve_df[curve_df["curve"] == "pr"],
        x="recall_curve",
        y="precision_curve",
        title=f"{stage.title}: Precision-Recall Curve",
        output_path=stage_dir / "pr_curve.png",
    )
    plot_attack_recall(
        stage,
        results_df[results_df["split"] == "test"],
        output_path=stage_dir / "attack_recall.png",
    )

    return results_df, curve_df, score_df


def evaluate_two_stage_policy(
    split_df: pd.DataFrame,
    all_results_df: pd.DataFrame,
    score_5_df: pd.DataFrame,
    score_full_df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    early_stage = STAGES[0]
    final_stage = STAGES[1]
    selected_early = rank_models(all_results_df, early_stage).iloc[0]
    selected_final = rank_models(all_results_df, final_stage).iloc[0]

    threshold_5 = float(selected_early["threshold"])
    threshold_full = float(selected_final["threshold"])
    early_model = str(selected_early["model"])
    final_model = str(selected_final["model"])

    early_scores = score_5_df[
        ["source_file", "flow_id", "label", early_model]
    ].rename(columns={early_model: "early_score"})
    final_scores = score_full_df[
        ["source_file", "flow_id", "label", final_model]
    ].rename(columns={final_model: "final_score"})

    joined = early_scores.merge(
        final_scores,
        on=["source_file", "flow_id", "label"],
        how="inner",
    )
    joined["early_positive"] = (joined["early_score"] >= threshold_5).astype(int)
    joined["final_positive"] = (joined["final_score"] >= threshold_full).astype(int)
    joined["any_stage_positive"] = (
        (joined["early_positive"] == 1) | (joined["final_positive"] == 1)
    ).astype(int)

    policy_rows: list[dict[str, str | float]] = []
    metrics_rows: list[dict[str, str | float]] = []

    for stage_name, pred_column in [
        ("early_warning", "early_positive"),
        ("final_confirmation", "final_positive"),
        ("any_stage", "any_stage_positive"),
    ]:
        predictions = joined[pred_column].to_numpy()
        y_true = (joined["label"] != "NORMAL").astype(int).to_numpy()
        normal_mask = joined["label"] == "NORMAL"

        metrics_rows.append(
            {
                "stage": stage_name,
                "model_5": early_model,
                "model_full": final_model,
                "threshold_5": threshold_5,
                "threshold_full": threshold_full,
                "precision": float(precision_score(y_true, predictions, zero_division=0)),
                "recall": float(recall_score(y_true, predictions, zero_division=0)),
                "f1": float(f1_score(y_true, predictions, zero_division=0)),
                "normal_fpr": float(predictions[normal_mask].mean()) if normal_mask.any() else np.nan,
            }
        )

        for label_name in ["NORMAL"] + ATTACK_ORDER:
            label_mask = joined["label"] == label_name
            if not label_mask.any():
                continue
            policy_rows.append(
                {
                    "stage": stage_name,
                    "label": label_name,
                    "flag_rate": float(predictions[label_mask].mean()),
                }
            )

    policy_df = pd.DataFrame(policy_rows)
    metrics_df = pd.DataFrame(metrics_rows)
    joined.to_csv(OUTPUT_ROOT / "two_stage_common_test_scores.csv", index=False)
    policy_df.to_csv(OUTPUT_ROOT / "two_stage_policy_rates.csv", index=False)
    metrics_df.to_csv(OUTPUT_ROOT / "two_stage_policy_metrics.csv", index=False)
    plot_stage_policy(policy_df, OUTPUT_ROOT / "two_stage_policy.png")

    with open(OUTPUT_ROOT / "selected_models.json", "w", encoding="utf-8") as handle:
        json.dump(
            {
                "early": {
                    "dataset": "5",
                    "model": early_model,
                    "threshold": threshold_5,
                },
                "final": {
                    "dataset": "full",
                    "model": final_model,
                    "threshold": threshold_full,
                },
            },
            handle,
            indent=2,
        )

    return policy_df, metrics_df


def write_markdown_summary(
    all_results_df: pd.DataFrame,
    two_stage_metrics_df: pd.DataFrame,
) -> None:
    early_best = rank_models(all_results_df, STAGES[0]).iloc[0]
    final_best = rank_models(all_results_df, STAGES[1]).iloc[0]

    lines = [
        "# Anomaly Experiment Summary",
        "",
        "## Best models",
        "",
        f"- Early warning (`merged_5.csv`): `{early_best['model']}`",
        f"  - Test recall: `{early_best['recall']:.4f}`",
        f"  - Test precision: `{early_best['precision']:.4f}`",
        f"  - Test F1: `{early_best['f1']:.4f}`",
        f"  - Test normal FPR: `{early_best['normal_fpr']:.4f}`",
        "",
        f"- Final confirmation (`merged_full.csv`): `{final_best['model']}`",
        f"  - Test recall: `{final_best['recall']:.4f}`",
        f"  - Test precision: `{final_best['precision']:.4f}`",
        f"  - Test F1: `{final_best['f1']:.4f}`",
        f"  - Test normal FPR: `{final_best['normal_fpr']:.4f}`",
        "",
        "## Two-stage policy",
        "",
    ]

    for row in two_stage_metrics_df.itertuples():
        lines.extend(
            [
                f"- `{row.stage}`",
                f"  - Precision: `{row.precision:.4f}`",
                f"  - Recall: `{row.recall:.4f}`",
                f"  - F1: `{row.f1:.4f}`",
                f"  - Normal FPR: `{row.normal_fpr:.4f}`",
            ]
        )

    summary_path = OUTPUT_ROOT / "summary.md"
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    sns.set_theme(style="whitegrid")
    split_df = build_source_file_split()
    all_results: list[pd.DataFrame] = []
    stage_scores: dict[str, pd.DataFrame] = {}

    for stage in STAGES:
        results_df, _, score_df = run_stage(stage, split_df)
        all_results.append(results_df)
        stage_scores[stage.dataset_name] = score_df

        best_model_row = rank_models(results_df, stage).iloc[0]
        plot_score_distribution(
            stage,
            score_df,
            str(best_model_row["model"]),
            float(best_model_row["threshold"]),
            OUTPUT_ROOT / stage.dataset_name / "best_score_distribution.png",
        )

    all_results_df = pd.concat(all_results, ignore_index=True)
    all_results_df.to_csv(OUTPUT_ROOT / "model_results.csv", index=False)

    test_only = all_results_df[all_results_df["split"] == "test"].copy()
    comparison_df = test_only[
        [
            "dataset",
            "stage",
            "objective",
            "model",
            "roc_auc",
            "pr_auc",
            "precision",
            "recall",
            "f1",
            "normal_fpr",
            "recall_get_flood",
            "recall_connection_flood",
            "recall_scan",
        ]
    ].sort_values(["dataset", "model"])
    comparison_df.to_csv(OUTPUT_ROOT / "test_model_comparison.csv", index=False)

    _, two_stage_metrics_df = evaluate_two_stage_policy(
        split_df,
        all_results_df,
        stage_scores["5"],
        stage_scores["full"],
    )
    write_markdown_summary(all_results_df, two_stage_metrics_df)

    print("\nArtifacts written to:")
    print(f"  {OUTPUT_ROOT}")


if __name__ == "__main__":
    main()
