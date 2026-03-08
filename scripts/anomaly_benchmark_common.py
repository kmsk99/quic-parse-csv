from __future__ import annotations

import json
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.exceptions import ConvergenceWarning
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import StandardScaler

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config  # noqa: E402
from anomaly_benchmark_models import ModelSpec  # noqa: E402


warnings.filterwarnings("ignore", category=ConvergenceWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)

RANDOM_SEED = config.RANDOM_SEED
MERGED_DIR = config.MERGED_DIR
BENCHMARK_ROOT = config.MODEL_DIR / "anomaly_benchmark"
DOCS_DIR = ROOT_DIR / "docs"

BENCHMARK_ROOT.mkdir(parents=True, exist_ok=True)
DOCS_DIR.mkdir(parents=True, exist_ok=True)

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
    "split",
    "is_anomaly",
}

ATTACK_ORDER = ["GET_FLOOD", "CONNECTION_FLOOD", "SCAN"]
STAGE_ORDER = ["5", "full"]


@dataclass(frozen=True)
class StageConfig:
    dataset_name: str
    title: str
    objective: str
    max_normal_fpr: float


STAGES = [
    StageConfig("5", "Early Warning (5 packets)", "early", 0.10),
    StageConfig("full", "Final Confirmation (full flow)", "final", 0.05),
]


def get_stage(dataset_name: str) -> StageConfig:
    for stage in STAGES:
        if stage.dataset_name == dataset_name:
            return stage
    raise KeyError(dataset_name)


def benchmark_split_path() -> Path:
    return BENCHMARK_ROOT / "source_file_split.csv"


def build_source_file_split() -> pd.DataFrame:
    split_path = benchmark_split_path()
    if split_path.exists():
        return pd.read_csv(split_path)

    reference = pd.read_csv(MERGED_DIR / "merged_full.csv", usecols=["label", "source_file"])
    grouped = (
        reference.drop_duplicates()
        .groupby("label")["source_file"]
        .apply(lambda values: sorted(values.unique()))
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
            assignments = [("valid", name) for name in shuffled[:valid_count]] + [
                ("test", name) for name in shuffled[valid_count:]
            ]

        for split_name, source_file in assignments:
            rows.append({"label": label, "source_file": source_file, "split": split_name})

    split_df = pd.DataFrame(rows).sort_values(["label", "split", "source_file"]).reset_index(drop=True)
    split_df.to_csv(split_path, index=False)
    return split_df


def load_stage_dataframe(dataset_name: str, split_df: pd.DataFrame) -> pd.DataFrame:
    data_path = MERGED_DIR / f"merged_{dataset_name}.csv"
    df = pd.read_csv(data_path)
    merged = df.merge(split_df, on=["label", "source_file"], how="inner").copy()
    return merged.assign(is_anomaly=(merged["label"] != "NORMAL").astype(int))


def get_feature_columns(df: pd.DataFrame) -> list[str]:
    return [
        column
        for column in df.columns
        if column not in EXCLUDED_FEATURES and pd.api.types.is_numeric_dtype(df[column])
    ]


def split_partitions(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    train_df = df[(df["split"] == "train") & (df["label"] == "NORMAL")].copy()
    valid_df = df[df["split"] == "valid"].copy()
    test_df = df[df["split"] == "test"].copy()
    return train_df, valid_df, test_df


def maybe_scale(
    train_df: pd.DataFrame,
    valid_df: pd.DataFrame,
    test_df: pd.DataFrame,
    feature_columns: list[str],
    use_scaler: bool,
) -> tuple[Any | None, np.ndarray, np.ndarray, np.ndarray]:
    x_train = train_df[feature_columns].fillna(0.0).to_numpy(dtype=float)
    x_valid = valid_df[feature_columns].fillna(0.0).to_numpy(dtype=float)
    x_test = test_df[feature_columns].fillna(0.0).to_numpy(dtype=float)

    if not use_scaler:
        return None, x_train, x_valid, x_test

    scaler = StandardScaler()
    return (
        scaler,
        scaler.fit_transform(x_train),
        scaler.transform(x_valid),
        scaler.transform(x_test),
    )


def evaluate_at_threshold(
    y_true: np.ndarray,
    scores: np.ndarray,
    labels: np.ndarray,
    threshold: float,
) -> dict[str, float]:
    predictions = (scores >= threshold).astype(int)
    normal_mask = labels == "NORMAL"
    anomaly_mask = ~normal_mask
    payload = {
        "threshold": float(threshold),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "normal_fpr": float(predictions[normal_mask].mean()) if normal_mask.any() else np.nan,
        "anomaly_recall": float(predictions[anomaly_mask].mean()) if anomaly_mask.any() else np.nan,
    }
    for attack_label in ATTACK_ORDER:
        attack_mask = labels == attack_label
        payload[f"recall_{attack_label.lower()}"] = (
            float(predictions[attack_mask].mean()) if attack_mask.any() else np.nan
        )
    return payload


def select_threshold(
    stage: StageConfig,
    y_valid: np.ndarray,
    scores_valid: np.ndarray,
    labels_valid: np.ndarray,
) -> dict[str, float]:
    normal_scores = scores_valid[labels_valid == "NORMAL"]
    quantiles = np.linspace(0.50, 0.999, 300)
    candidate_thresholds = np.unique(np.quantile(normal_scores, quantiles))

    best_payload: dict[str, float] | None = None
    best_key: tuple[float, float, float] | None = None

    for threshold in candidate_thresholds:
        metrics = evaluate_at_threshold(y_valid, scores_valid, labels_valid, float(threshold))
        if metrics["normal_fpr"] > stage.max_normal_fpr:
            continue

        if stage.objective == "early":
            key = (metrics["anomaly_recall"], metrics["precision"], -metrics["normal_fpr"])
        else:
            key = (metrics["f1"], metrics["precision"], -metrics["normal_fpr"])

        if best_key is None or key > best_key:
            best_key = key
            best_payload = metrics

    if best_payload is None:
        fallback_threshold = float(np.quantile(normal_scores, 1.0 - stage.max_normal_fpr))
        best_payload = evaluate_at_threshold(y_valid, scores_valid, labels_valid, fallback_threshold)

    return best_payload


def row_metrics(
    stage: StageConfig,
    split_name: str,
    model_name: str,
    scores: np.ndarray,
    y_true: np.ndarray,
    labels: np.ndarray,
    threshold: float,
) -> dict[str, float | str]:
    payload = {
        "dataset": stage.dataset_name,
        "stage": stage.title,
        "objective": stage.objective,
        "split": split_name,
        "model": model_name,
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "pr_auc": float(average_precision_score(y_true, scores)),
    }
    payload.update(evaluate_at_threshold(y_true, scores, labels, threshold))
    return payload


def plot_roc_pr(results_df: pd.DataFrame, model_dir: Path) -> None:
    curve_payload: list[tuple[str, np.ndarray, np.ndarray]] = []
    pr_payload: list[tuple[str, np.ndarray, np.ndarray]] = []

    for dataset_name in STAGE_ORDER:
        stage_dir = model_dir / dataset_name
        test_scores = pd.read_csv(stage_dir / "test_scores.csv")
        y_true = (test_scores["label"] != "NORMAL").astype(int).to_numpy()
        scores = test_scores["score"].to_numpy()

        fpr, tpr, _ = roc_curve(y_true, scores)
        precision_curve, recall_curve, _ = precision_recall_curve(y_true, scores)
        curve_payload.append((dataset_name, fpr, tpr))
        pr_payload.append((dataset_name, recall_curve, precision_curve))

    plt.figure(figsize=(8, 6))
    for dataset_name, fpr, tpr in curve_payload:
        stage = get_stage(dataset_name)
        plt.plot(fpr, tpr, linewidth=2, label=stage.title)
    plt.plot([0, 1], [0, 1], linestyle="--", linewidth=1, color="#777777")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve by Stage")
    plt.legend()
    plt.tight_layout()
    plt.savefig(model_dir / "roc_curve.png", dpi=180)
    plt.close()

    plt.figure(figsize=(8, 6))
    for dataset_name, recall_curve, precision_curve in pr_payload:
        stage = get_stage(dataset_name)
        plt.plot(recall_curve, precision_curve, linewidth=2, label=stage.title)
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve by Stage")
    plt.legend()
    plt.tight_layout()
    plt.savefig(model_dir / "pr_curve.png", dpi=180)
    plt.close()


def plot_score_distribution(stage: StageConfig, model_dir: Path) -> None:
    stage_dir = model_dir / stage.dataset_name
    scores_df = pd.read_csv(stage_dir / "test_scores.csv")
    threshold_payload = json.loads((stage_dir / "threshold.json").read_text(encoding="utf-8"))
    threshold = threshold_payload["threshold"]

    scores_df["group"] = np.where(scores_df["label"] == "NORMAL", "NORMAL", "ABNORMAL")
    plt.figure(figsize=(9, 6))
    for group_name, color in [("NORMAL", "#4E79A7"), ("ABNORMAL", "#E15759")]:
        group_df = scores_df[scores_df["group"] == group_name]
        if group_df.empty:
            continue
        sns.kdeplot(
            group_df["score"],
            fill=True,
            alpha=0.35,
            linewidth=2,
            label=group_name,
            color=color,
        )
    plt.axvline(threshold, linestyle="--", linewidth=2, color="#222222", label="Threshold")
    plt.xlabel("Anomaly Score")
    plt.ylabel("Density")
    plt.title(f"{stage.title}: Score Distribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(stage_dir / "score_distribution.png", dpi=180)
    plt.close()


def plot_attack_recall(test_results: pd.DataFrame, model_dir: Path) -> None:
    chart_df = test_results[
        ["dataset", "recall_get_flood", "recall_connection_flood", "recall_scan"]
    ].melt(id_vars="dataset", var_name="attack", value_name="recall")
    chart_df["attack"] = (
        chart_df["attack"].str.replace("recall_", "", regex=False).str.upper().str.replace("_", " ", regex=False)
    )
    chart_df["dataset"] = chart_df["dataset"].map(
        {"5": "Early Warning (5 packets)", "full": "Final Confirmation (full flow)"}
    )

    plt.figure(figsize=(9, 6))
    sns.barplot(data=chart_df, x="attack", y="recall", hue="dataset")
    plt.ylim(0, 1.05)
    plt.xlabel("")
    plt.ylabel("Recall")
    plt.title("Attack Recall by Stage")
    plt.tight_layout()
    plt.savefig(model_dir / "attack_recall.png", dpi=180)
    plt.close()


def evaluate_two_stage_policy(model_name: str, model_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    early_scores = pd.read_csv(model_dir / "5" / "test_scores.csv")
    final_scores = pd.read_csv(model_dir / "full" / "test_scores.csv")
    early_threshold = json.loads((model_dir / "5" / "threshold.json").read_text(encoding="utf-8"))["threshold"]
    final_threshold = json.loads((model_dir / "full" / "threshold.json").read_text(encoding="utf-8"))["threshold"]

    joined = early_scores[["source_file", "flow_id", "label", "score"]].rename(columns={"score": "early_score"}).merge(
        final_scores[["source_file", "flow_id", "label", "score"]].rename(columns={"score": "final_score"}),
        on=["source_file", "flow_id", "label"],
        how="inner",
    )
    joined["early_positive"] = (joined["early_score"] >= early_threshold).astype(int)
    joined["final_positive"] = (joined["final_score"] >= final_threshold).astype(int)
    joined["any_stage_positive"] = (
        (joined["early_positive"] == 1) | (joined["final_positive"] == 1)
    ).astype(int)

    metrics_rows: list[dict[str, float | str]] = []
    rate_rows: list[dict[str, float | str]] = []
    y_true = (joined["label"] != "NORMAL").astype(int).to_numpy()
    normal_mask = joined["label"] == "NORMAL"

    for policy_name, column in [
        ("early_warning", "early_positive"),
        ("final_confirmation", "final_positive"),
        ("any_stage", "any_stage_positive"),
    ]:
        predictions = joined[column].to_numpy()
        metrics_rows.append(
            {
                "model": model_name,
                "policy": policy_name,
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
            rate_rows.append(
                {
                    "model": model_name,
                    "policy": policy_name,
                    "label": label_name,
                    "flag_rate": float(predictions[label_mask].mean()),
                }
            )

    joined.to_csv(model_dir / "two_stage_common_test_scores.csv", index=False)
    metrics_df = pd.DataFrame(metrics_rows)
    rates_df = pd.DataFrame(rate_rows)
    metrics_df.to_csv(model_dir / "two_stage_policy_metrics.csv", index=False)
    rates_df.to_csv(model_dir / "two_stage_policy_rates.csv", index=False)

    plt.figure(figsize=(9, 6))
    sns.barplot(data=rates_df, x="label", y="flag_rate", hue="policy")
    plt.ylim(0, 1.05)
    plt.xlabel("")
    plt.ylabel("Positive Rate")
    plt.title(f"{model_name}: Two-Stage Policy")
    plt.tight_layout()
    plt.savefig(model_dir / "two_stage_policy.png", dpi=180)
    plt.close()

    return metrics_df, rates_df


def infer_observations(test_results: pd.DataFrame, policy_metrics_df: pd.DataFrame) -> list[str]:
    early_row = test_results[test_results["dataset"] == "5"].iloc[0]
    final_row = test_results[test_results["dataset"] == "full"].iloc[0]
    any_stage_row = policy_metrics_df[policy_metrics_df["policy"] == "any_stage"].iloc[0]

    observations = []
    if early_row["recall"] > final_row["recall"]:
        observations.append(
            "초기 단계 재현율이 full 단계보다 높아서, 5패킷 모델이 더 공격적인 탐지기로 동작한다."
        )
    else:
        observations.append(
            "full 단계 재현율이 초기 단계와 같거나 더 높아서, 더 긴 flow 정보가 유의미한 확인 신호를 추가하고 있다."
        )

    hardest_attack = min(
        ATTACK_ORDER,
        key=lambda label: float(final_row[f"recall_{label.lower()}"]),
    )
    observations.append(
        f"최종 단계에서 가장 어려운 공격은 `{hardest_attack}`이며, 세 공격군 중 재현율이 가장 낮다."
    )

    if any_stage_row["normal_fpr"] > early_row["normal_fpr"] + 0.02:
        observations.append(
            "OR 형태의 2단계 정책은 재현율을 높이지만 정상 오탐도 함께 증가하므로 threshold 조정이 중요하다."
        )
    else:
        observations.append(
            "OR 형태의 2단계 정책은 정상 오탐을 크게 늘리지 않으면서 재현율을 높인다."
        )

    return observations


def write_model_doc(model_spec: ModelSpec, model_dir: Path, test_results: pd.DataFrame, policy_metrics_df: pd.DataFrame) -> Path:
    slug_to_doc = {
        "isolation_forest": "anomaly-isolation-forest.md",
        "hbos": "anomaly-hbos.md",
        "ecod": "anomaly-ecod.md",
        "pca_reconstruction": "anomaly-pca-reconstruction.md",
        "autoencoder": "anomaly-autoencoder.md",
    }
    doc_path = DOCS_DIR / slug_to_doc[model_spec.slug]
    early_row = test_results[test_results["dataset"] == "5"].iloc[0]
    final_row = test_results[test_results["dataset"] == "full"].iloc[0]
    observations = infer_observations(test_results, policy_metrics_df)
    policy_label_map = {
        "early_warning": "초기 경보",
        "final_confirmation": "최종 확인",
        "any_stage": "하나라도 탐지",
    }

    lines = [
        f"# {model_spec.name} 결과",
        "",
        "## 방법",
        "",
        model_spec.description,
        "",
        "## 테스트 성능",
        "",
        "### 초기 경보 (`merged_5.csv`)",
        "",
        f"- ROC-AUC: `{early_row['roc_auc']:.4f}`",
        f"- PR-AUC: `{early_row['pr_auc']:.4f}`",
        f"- 정밀도: `{early_row['precision']:.4f}`",
        f"- 재현율: `{early_row['recall']:.4f}`",
        f"- F1: `{early_row['f1']:.4f}`",
        f"- 정상 FPR: `{early_row['normal_fpr']:.4f}`",
        f"- GET_FLOOD 재현율: `{early_row['recall_get_flood']:.4f}`",
        f"- CONNECTION_FLOOD 재현율: `{early_row['recall_connection_flood']:.4f}`",
        f"- SCAN 재현율: `{early_row['recall_scan']:.4f}`",
        "",
        "### 최종 확인 (`merged_full.csv`)",
        "",
        f"- ROC-AUC: `{final_row['roc_auc']:.4f}`",
        f"- PR-AUC: `{final_row['pr_auc']:.4f}`",
        f"- 정밀도: `{final_row['precision']:.4f}`",
        f"- 재현율: `{final_row['recall']:.4f}`",
        f"- F1: `{final_row['f1']:.4f}`",
        f"- 정상 FPR: `{final_row['normal_fpr']:.4f}`",
        f"- GET_FLOOD 재현율: `{final_row['recall_get_flood']:.4f}`",
        f"- CONNECTION_FLOOD 재현율: `{final_row['recall_connection_flood']:.4f}`",
        f"- SCAN 재현율: `{final_row['recall_scan']:.4f}`",
        "",
        "## 2단계 정책",
        "",
    ]

    for row in policy_metrics_df.itertuples():
        lines.extend(
            [
                f"- `{policy_label_map.get(row.policy, row.policy)}`",
                f"  - 정밀도: `{row.precision:.4f}`",
                f"  - 재현율: `{row.recall:.4f}`",
                f"  - F1: `{row.f1:.4f}`",
                f"  - 정상 FPR: `{row.normal_fpr:.4f}`",
            ]
        )

    lines.extend(
        [
            "",
            "## 해석",
            "",
        ]
    )
    lines.extend([f"- {line}" for line in observations])
    lines.extend(
        [
            "",
            "## 시각화",
            "",
            f"![ROC](../prediction/anomaly_benchmark/{model_spec.slug}/roc_curve.png)",
            "",
            f"![PR](../prediction/anomaly_benchmark/{model_spec.slug}/pr_curve.png)",
            "",
            f"![공격 재현율](../prediction/anomaly_benchmark/{model_spec.slug}/attack_recall.png)",
            "",
            f"![2단계 정책](../prediction/anomaly_benchmark/{model_spec.slug}/two_stage_policy.png)",
            "",
            "## 산출물",
            "",
            f"- `prediction/anomaly_benchmark/{model_spec.slug}/model_results.csv`",
            f"- `prediction/anomaly_benchmark/{model_spec.slug}/two_stage_policy_metrics.csv`",
            f"- `prediction/anomaly_benchmark/{model_spec.slug}/summary.json`",
        ]
    )

    doc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return doc_path


def run_single_model(model_spec: ModelSpec) -> dict[str, Any]:
    sns.set_theme(style="whitegrid")
    split_df = build_source_file_split()
    model_dir = BENCHMARK_ROOT / model_spec.slug
    model_dir.mkdir(parents=True, exist_ok=True)

    all_rows: list[dict[str, float | str]] = []

    for stage in STAGES:
        df = load_stage_dataframe(stage.dataset_name, split_df)
        feature_columns = get_feature_columns(df)
        train_df, valid_df, test_df = split_partitions(df)
        scaler, x_train, x_valid, x_test = maybe_scale(
            train_df,
            valid_df,
            test_df,
            feature_columns,
            use_scaler=model_spec.use_scaler,
        )

        detector = model_spec.builder()
        detector.fit(x_train)
        train_scores = detector.decision_function(x_train)
        valid_scores = detector.decision_function(x_valid)
        test_scores = detector.decision_function(x_test)

        y_valid = valid_df["is_anomaly"].to_numpy()
        y_test = test_df["is_anomaly"].to_numpy()
        labels_valid = valid_df["label"].to_numpy()
        labels_test = test_df["label"].to_numpy()

        threshold_payload = select_threshold(stage, y_valid, valid_scores, labels_valid)
        threshold = float(threshold_payload["threshold"])

        all_rows.append(
            row_metrics(stage, "valid", model_spec.name, valid_scores, y_valid, labels_valid, threshold)
        )
        all_rows.append(
            row_metrics(stage, "test", model_spec.name, test_scores, y_test, labels_test, threshold)
        )

        stage_dir = model_dir / stage.dataset_name
        stage_dir.mkdir(parents=True, exist_ok=True)
        stage_scores_df = pd.DataFrame(
            {
                "source_file": test_df["source_file"].to_numpy(),
                "flow_id": test_df["flow_id"].to_numpy(),
                "label": labels_test,
                "score": test_scores,
            }
        )
        stage_scores_df.to_csv(stage_dir / "test_scores.csv", index=False)

        with open(stage_dir / "threshold.json", "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "stage": stage.title,
                    "objective": stage.objective,
                    "threshold": threshold,
                    "max_normal_fpr": stage.max_normal_fpr,
                    "valid_metrics": threshold_payload,
                    "metadata": detector.metadata(),
                },
                handle,
                indent=2,
            )

        joblib.dump(
            {
                "model": detector,
                "scaler": scaler,
                "feature_columns": feature_columns,
                "metadata": detector.metadata(),
            },
            stage_dir / "artifact.pkl",
        )

    results_df = pd.DataFrame(all_rows)
    results_df.to_csv(model_dir / "model_results.csv", index=False)
    test_results = results_df[results_df["split"] == "test"].sort_values("dataset").reset_index(drop=True)
    test_results.to_csv(model_dir / "test_results.csv", index=False)

    plot_roc_pr(results_df, model_dir)
    for stage in STAGES:
        plot_score_distribution(stage, model_dir)
    plot_attack_recall(test_results, model_dir)
    policy_metrics_df, policy_rates_df = evaluate_two_stage_policy(model_spec.name, model_dir)

    summary = {
        "model": model_spec.name,
        "slug": model_spec.slug,
        "test_results": test_results.to_dict(orient="records"),
        "two_stage_policy": policy_metrics_df.to_dict(orient="records"),
    }
    with open(model_dir / "summary.json", "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    doc_path = write_model_doc(model_spec, model_dir, test_results, policy_metrics_df)
    return {
        "model": model_spec.name,
        "slug": model_spec.slug,
        "model_dir": model_dir,
        "doc_path": doc_path,
        "test_results": test_results,
        "policy_metrics": policy_metrics_df,
        "policy_rates": policy_rates_df,
    }


def generate_comparison_artifacts(model_runs: list[dict[str, Any]]) -> Path:
    comparison_dir = BENCHMARK_ROOT / "comparison"
    comparison_dir.mkdir(parents=True, exist_ok=True)

    test_frames = []
    policy_frames = []
    for item in model_runs:
        test_frames.append(item["test_results"].assign(model=item["model"], slug=item["slug"]))
        policy_frames.append(item["policy_metrics"].assign(model=item["model"], slug=item["slug"]))

    test_df = pd.concat(test_frames, ignore_index=True)
    policy_df = pd.concat(policy_frames, ignore_index=True)
    test_df.to_csv(comparison_dir / "test_model_comparison.csv", index=False)
    policy_df.to_csv(comparison_dir / "policy_comparison.csv", index=False)

    display_test_df = test_df.copy()
    display_test_df["dataset"] = display_test_df["dataset"].map({"5": "5", "full": "full"})
    display_test_df["stage"] = display_test_df["stage"].map(
        {
            "Early Warning (5 packets)": "초기 경보 (5패킷)",
            "Final Confirmation (full flow)": "최종 확인 (전체 flow)",
        }
    )
    display_test_df["objective"] = display_test_df["objective"].map(
        {"early": "초기", "final": "최종"}
    )
    display_test_df["split"] = display_test_df["split"].map(
        {"test": "테스트", "valid": "검증", "train": "학습"}
    )
    display_test_df = display_test_df.rename(
        columns={
            "dataset": "데이터셋",
            "stage": "단계",
            "objective": "목적",
            "split": "분할",
            "model": "모델",
            "roc_auc": "ROC-AUC",
            "pr_auc": "PR-AUC",
            "threshold": "임계값",
            "precision": "정밀도",
            "recall": "재현율",
            "f1": "F1",
            "normal_fpr": "정상 FPR",
            "anomaly_recall": "이상 재현율",
            "recall_get_flood": "GET_FLOOD 재현율",
            "recall_connection_flood": "CONNECTION_FLOOD 재현율",
            "recall_scan": "SCAN 재현율",
            "slug": "slug",
        }
    )

    display_policy_df = policy_df.copy()
    display_policy_df["policy"] = display_policy_df["policy"].map(
        {
            "early_warning": "초기 경보",
            "final_confirmation": "최종 확인",
            "any_stage": "하나라도 탐지",
        }
    )
    display_policy_df = display_policy_df.rename(
        columns={
            "model": "모델",
            "policy": "정책",
            "precision": "정밀도",
            "recall": "재현율",
            "f1": "F1",
            "normal_fpr": "정상 FPR",
            "slug": "slug",
        }
    )

    for metric in ["recall", "f1", "normal_fpr"]:
        plt.figure(figsize=(10, 6))
        sns.barplot(data=test_df, x="model", y=metric, hue="dataset")
        plt.title(f"Model Comparison: {metric.upper()} by Stage")
        plt.xlabel("")
        plt.tight_layout()
        plt.savefig(comparison_dir / f"{metric}_by_stage.png", dpi=180)
        plt.close()

    plt.figure(figsize=(10, 6))
    sns.barplot(data=policy_df, x="model", y="f1", hue="policy")
    plt.title("Two-Stage Policy F1 by Model")
    plt.xlabel("")
    plt.tight_layout()
    plt.savefig(comparison_dir / "policy_f1.png", dpi=180)
    plt.close()

    best_early = (
        test_df[test_df["dataset"] == "5"]
        .sort_values(["recall", "precision", "normal_fpr"], ascending=[False, False, True])
        .iloc[0]
    )
    best_final = (
        test_df[test_df["dataset"] == "full"]
        .sort_values(["f1", "precision", "normal_fpr"], ascending=[False, False, True])
        .iloc[0]
    )
    lowest_fpr_final = (
        test_df[test_df["dataset"] == "full"]
        .sort_values(["normal_fpr", "f1"], ascending=[True, False])
        .iloc[0]
    )

    lines = [
        "# 표 형식 이상 탐지 벤치마크 비교",
        "",
        "## 실험 설정",
        "",
        "- 데이터: `merged_5.csv`, `merged_full.csv`",
        "- 학습 분할: `NORMAL`만 사용",
        "- 검증/테스트 분할: `NORMAL + ABNORMAL`",
        "- 분할 단위: `source_file`",
        "- threshold 정책:",
        "  - 초기 단계: `normal FPR <= 10%` 조건에서 이상 재현율 최대화",
        "  - 최종 단계: validation에서 `normal FPR <= 5%` 조건으로 F1 최대화",
        "",
        "## 핵심 결과",
        "",
        f"- 초기 단계 최고 재현율: `{best_early['model']}` / 재현율 `{best_early['recall']:.4f}` / 정상 FPR `{best_early['normal_fpr']:.4f}`",
        f"- 최종 단계 최고 F1: `{best_final['model']}` / F1 `{best_final['f1']:.4f}` / 정상 FPR `{best_final['normal_fpr']:.4f}`",
        f"- 최종 단계 최저 정상 FPR: `{lowest_fpr_final['model']}` / 정상 FPR `{lowest_fpr_final['normal_fpr']:.4f}` / F1 `{lowest_fpr_final['f1']:.4f}`",
        "",
        "## 해석",
        "",
        "- `Autoencoder`가 전체적으로 가장 강했다. 초기 단계 재현율과 최종 단계 F1 모두 우세하지만, 정상 FPR이 약 10% 수준이라 운영용으로는 threshold 재조정이 필요하다.",
        "- `HBOS`는 가벼운 고전적 baseline으로는 괜찮지만, 정상 오탐이 높고 full 단계에서 SCAN 재현율이 크게 무너진다.",
        "- `ECOD`는 초기 단계에서는 약하고 full 단계에서 강해진다. 조기 탐지기보다 보수적인 최종 확인기 성격에 가깝다.",
        "- `PCA reconstruction`은 초기 경보 성능은 약하지만 full flow가 주어지면 경쟁력이 생긴다. 공격 유형별 편차가 커서 초기 모델보다는 full baseline으로 보는 편이 맞다.",
        "- `IsolationForest`는 이번 데이터에서는 다섯 방법 중 가장 약했다. 주력 후보보다는 참조 baseline으로 보는 편이 적절하다.",
        "",
        "## 권장 사항",
        "",
        "- 목표가 false negative 최소화라면 `merged_5.csv` 기준 `Autoencoder`부터 시작하고, 이후 정상 FPR을 줄이는 방향으로 threshold를 다시 잡는 것이 좋다.",
        "- 논문용 고전 baseline은 `HBOS`, `ECOD`, `PCA reconstruction`을 중심으로 두는 것이 적절하다.",
        "- `Autoencoder`가 고전 모델보다 많이 강하므로, 다음 단계에서는 unseen capture/session 또는 더 강한 홀드아웃 환경에서 일반화 성능을 다시 검증해야 한다.",
        "",
        "## 테스트 비교 표",
        "",
        display_test_df.to_markdown(index=False),
        "",
        "## 2단계 정책 비교 표",
        "",
        display_policy_df.to_markdown(index=False),
        "",
        "## 시각화",
        "",
        "![단계별 재현율](../prediction/anomaly_benchmark/comparison/recall_by_stage.png)",
        "",
        "![단계별 F1](../prediction/anomaly_benchmark/comparison/f1_by_stage.png)",
        "",
        "![단계별 정상 FPR](../prediction/anomaly_benchmark/comparison/normal_fpr_by_stage.png)",
        "",
        "![정책별 F1](../prediction/anomaly_benchmark/comparison/policy_f1.png)",
        "",
        "## 개별 문서",
        "",
        "- [Isolation Forest](./anomaly-isolation-forest.md)",
        "- [HBOS](./anomaly-hbos.md)",
        "- [ECOD](./anomaly-ecod.md)",
        "- [PCA Reconstruction](./anomaly-pca-reconstruction.md)",
        "- [Autoencoder](./anomaly-autoencoder.md)",
        "",
    ]

    doc_path = DOCS_DIR / "anomaly-benchmark-comparison.md"
    doc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return doc_path
