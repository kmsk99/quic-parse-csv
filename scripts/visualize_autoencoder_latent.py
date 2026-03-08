from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import seaborn as sns
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config  # noqa: E402
from anomaly_benchmark_common import (  # noqa: E402
    BENCHMARK_ROOT,
    DOCS_DIR,
    build_source_file_split,
    get_stage,
    load_stage_dataframe,
    split_partitions,
)


AUTOENCODER_ROOT = BENCHMARK_ROOT / "autoencoder"
DOC_PATH = DOCS_DIR / "anomaly-autoencoder-latent.md"
RANDOM_SEED = config.RANDOM_SEED
LABEL_ORDER = ["NORMAL", "GET_FLOOD", "CONNECTION_FLOOD", "SCAN"]
LABEL_COLORS = {
    "NORMAL": "#4E79A7",
    "GET_FLOOD": "#E15759",
    "CONNECTION_FLOOD": "#F28E2B",
    "SCAN": "#59A14F",
}
MAX_POINTS_PER_LABEL = 2500


def sample_balanced(df: pd.DataFrame, max_points_per_label: int) -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_SEED)
    sampled_frames = []
    for label in LABEL_ORDER:
        label_df = df[df["label"] == label]
        if label_df.empty:
            continue
        if len(label_df) <= max_points_per_label:
            sampled_frames.append(label_df.copy())
            continue
        indices = rng.choice(label_df.index.to_numpy(), size=max_points_per_label, replace=False)
        sampled_frames.append(label_df.loc[np.sort(indices)].copy())
    return pd.concat(sampled_frames).sort_index()


def plot_projection(
    df: pd.DataFrame,
    x_col: str,
    y_col: str,
    title: str,
    output_path: Path,
) -> None:
    plt.figure(figsize=(9, 7))
    for label in LABEL_ORDER:
        label_df = df[df["label"] == label]
        if label_df.empty:
            continue
        plt.scatter(
            label_df[x_col],
            label_df[y_col],
            s=10,
            alpha=0.55,
            label=label,
            color=LABEL_COLORS[label],
            edgecolors="none",
        )
    plt.xlabel(x_col.upper())
    plt.ylabel(y_col.upper())
    plt.title(title)
    plt.legend(markerscale=2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def plot_projection_3d_png(
    df: pd.DataFrame,
    x_col: str,
    y_col: str,
    z_col: str,
    title: str,
    output_path: Path,
) -> None:
    figure = plt.figure(figsize=(9, 7))
    axis = figure.add_subplot(111, projection="3d")
    for label in LABEL_ORDER:
        label_df = df[df["label"] == label]
        if label_df.empty:
            continue
        axis.scatter(
            label_df[x_col],
            label_df[y_col],
            label_df[z_col],
            s=10,
            alpha=0.45,
            label=label,
            color=LABEL_COLORS[label],
            depthshade=False,
        )
    axis.set_xlabel(x_col.upper())
    axis.set_ylabel(y_col.upper())
    axis.set_zlabel(z_col.upper())
    axis.set_title(title)
    axis.view_init(elev=24, azim=36)
    axis.legend(markerscale=2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def plot_projection_3d_html(
    df: pd.DataFrame,
    x_col: str,
    y_col: str,
    z_col: str,
    title: str,
    output_path: Path,
) -> None:
    figure = go.Figure()
    for label in LABEL_ORDER:
        label_df = df[df["label"] == label]
        if label_df.empty:
            continue
        figure.add_trace(
            go.Scatter3d(
                x=label_df[x_col],
                y=label_df[y_col],
                z=label_df[z_col],
                mode="markers",
                name=label,
                marker={
                    "size": 3,
                    "opacity": 0.6,
                    "color": LABEL_COLORS[label],
                },
                customdata=np.stack(
                    [
                        label_df["source_file"].to_numpy(),
                        label_df["flow_id"].to_numpy(),
                    ],
                    axis=1,
                ),
                hovertemplate=(
                    "label=%{text}<br>"
                    "source=%{customdata[0]}<br>"
                    "flow=%{customdata[1]}<br>"
                    f"{x_col}=%{{x:.3f}}<br>"
                    f"{y_col}=%{{y:.3f}}<br>"
                    f"{z_col}=%{{z:.3f}}<extra></extra>"
                ),
                text=label_df["label"],
            )
        )

    figure.update_layout(
        title=title,
        scene={
            "xaxis_title": x_col.upper(),
            "yaxis_title": y_col.upper(),
            "zaxis_title": z_col.upper(),
        },
        width=980,
        height=760,
        margin={"l": 0, "r": 0, "t": 50, "b": 0},
    )
    figure.write_html(output_path, full_html=True, include_plotlyjs=True)


def plot_centroid_distance(distance_df: pd.DataFrame, output_path: Path, stage_title: str) -> None:
    plt.figure(figsize=(8, 5))
    sns.barplot(
        data=distance_df,
        x="label",
        y="distance_to_normal",
        hue="label",
        palette=LABEL_COLORS,
        dodge=False,
        legend=False,
    )
    plt.xlabel("")
    plt.ylabel("Distance to NORMAL centroid")
    plt.title(f"{stage_title}: Latent centroid distance")
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def summarize_stage(stage_name: str, split_df: pd.DataFrame) -> dict[str, object]:
    stage = get_stage(stage_name)
    stage_dir = AUTOENCODER_ROOT / stage_name
    artifact = joblib.load(stage_dir / "artifact.pkl")

    df = load_stage_dataframe(stage_name, split_df)
    _, _, test_df = split_partitions(df)

    x_test = test_df[artifact["feature_columns"]].fillna(0.0).to_numpy(dtype=float)
    scaler = artifact["scaler"]
    if scaler is not None:
        x_test = scaler.transform(x_test)

    detector = artifact["model"]
    latent = detector.encode(x_test)
    latent_scaled = StandardScaler().fit_transform(latent)

    latent_columns = [f"latent_{index:02d}" for index in range(latent_scaled.shape[1])]
    latent_df = test_df[["source_file", "flow_id", "label"]].reset_index(drop=True).copy()
    latent_df[latent_columns] = latent_scaled
    latent_df.to_csv(stage_dir / "latent_embedding_test.csv", index=False)

    pca = PCA(n_components=2, random_state=RANDOM_SEED)
    pca_coords = pca.fit_transform(latent_scaled)
    pca_df = latent_df[["source_file", "flow_id", "label"]].copy()
    pca_df["pc1"] = pca_coords[:, 0]
    pca_df["pc2"] = pca_coords[:, 1]
    pca_df.to_csv(stage_dir / "latent_projection_pca.csv", index=False)
    plot_projection(
        pca_df,
        "pc1",
        "pc2",
        f"{stage.title}: Bottleneck PCA projection",
        stage_dir / "latent_pca.png",
    )

    pca_3d = PCA(n_components=3, random_state=RANDOM_SEED)
    pca_3d_coords = pca_3d.fit_transform(latent_scaled)
    pca_3d_df = latent_df[["source_file", "flow_id", "label"]].copy()
    pca_3d_df["pc1"] = pca_3d_coords[:, 0]
    pca_3d_df["pc2"] = pca_3d_coords[:, 1]
    pca_3d_df["pc3"] = pca_3d_coords[:, 2]
    pca_3d_df.to_csv(stage_dir / "latent_projection_pca3d.csv", index=False)

    sampled_df = sample_balanced(latent_df, MAX_POINTS_PER_LABEL)
    sampled_indices = sampled_df.index.to_numpy()
    sampled_latent = latent_scaled[sampled_indices]

    sampled_pca_3d_df = pca_3d_df.loc[sampled_indices].copy()
    sampled_pca_3d_df.to_csv(stage_dir / "latent_projection_pca3d_sample.csv", index=False)
    plot_projection_3d_png(
        sampled_pca_3d_df,
        "pc1",
        "pc2",
        "pc3",
        f"{stage.title}: Bottleneck PCA 3D projection",
        stage_dir / "latent_pca_3d.png",
    )
    plot_projection_3d_html(
        sampled_pca_3d_df,
        "pc1",
        "pc2",
        "pc3",
        f"{stage.title}: Bottleneck PCA 3D projection",
        stage_dir / "latent_pca_3d.html",
    )

    tsne = TSNE(
        n_components=2,
        init="pca",
        learning_rate="auto",
        perplexity=40,
        random_state=RANDOM_SEED,
    )
    tsne_coords = tsne.fit_transform(sampled_latent)
    tsne_df = sampled_df[["source_file", "flow_id", "label"]].copy()
    tsne_df["tsne_1"] = tsne_coords[:, 0]
    tsne_df["tsne_2"] = tsne_coords[:, 1]
    tsne_df.to_csv(stage_dir / "latent_projection_tsne_sample.csv", index=False)
    plot_projection(
        tsne_df,
        "tsne_1",
        "tsne_2",
        f"{stage.title}: Bottleneck t-SNE projection",
        stage_dir / "latent_tsne.png",
    )

    tsne_3d = TSNE(
        n_components=3,
        init="pca",
        learning_rate="auto",
        perplexity=40,
        random_state=RANDOM_SEED,
    )
    tsne_3d_coords = tsne_3d.fit_transform(sampled_latent)
    tsne_3d_df = sampled_df[["source_file", "flow_id", "label"]].copy()
    tsne_3d_df["tsne_1"] = tsne_3d_coords[:, 0]
    tsne_3d_df["tsne_2"] = tsne_3d_coords[:, 1]
    tsne_3d_df["tsne_3"] = tsne_3d_coords[:, 2]
    tsne_3d_df.to_csv(stage_dir / "latent_projection_tsne3d_sample.csv", index=False)
    plot_projection_3d_png(
        tsne_3d_df,
        "tsne_1",
        "tsne_2",
        "tsne_3",
        f"{stage.title}: Bottleneck t-SNE 3D projection",
        stage_dir / "latent_tsne_3d.png",
    )
    plot_projection_3d_html(
        tsne_3d_df,
        "tsne_1",
        "tsne_2",
        "tsne_3",
        f"{stage.title}: Bottleneck t-SNE 3D projection",
        stage_dir / "latent_tsne_3d.html",
    )

    centroid_rows = []
    centroids = {
        label: latent_scaled[latent_df["label"] == label].mean(axis=0)
        for label in LABEL_ORDER
        if (latent_df["label"] == label).any()
    }
    normal_centroid = centroids["NORMAL"]
    for label, centroid in centroids.items():
        if label == "NORMAL":
            continue
        centroid_rows.append(
            {
                "stage": stage_name,
                "label": label,
                "distance_to_normal": float(np.linalg.norm(centroid - normal_centroid)),
            }
        )

    centroid_df = pd.DataFrame(centroid_rows)
    centroid_df.to_csv(stage_dir / "latent_centroid_distance.csv", index=False)
    plot_centroid_distance(centroid_df, stage_dir / "latent_centroid_distance.png", stage.title)

    sampled_labels = tsne_df["label"].to_numpy()
    sampled_binary_labels = np.where(sampled_labels == "NORMAL", "NORMAL", "ABNORMAL")
    metrics = {
        "stage": stage_name,
        "stage_title": stage.title,
        "test_rows": int(len(test_df)),
        "latent_dim": int(latent_scaled.shape[1]),
        "sampled_rows_for_tsne": int(len(tsne_df)),
        "pca_explained_variance_ratio": [float(value) for value in pca.explained_variance_ratio_],
        "pca3d_explained_variance_ratio": [float(value) for value in pca_3d.explained_variance_ratio_],
        "silhouette_multiclass": float(silhouette_score(sampled_latent, sampled_labels)),
        "silhouette_binary": float(silhouette_score(sampled_latent, sampled_binary_labels)),
    }
    with open(stage_dir / "latent_metrics.json", "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)

    return {
        "metrics": metrics,
        "centroid_df": centroid_df,
    }


def write_doc(stage_summaries: list[dict[str, object]]) -> Path:
    stage_map = {summary["metrics"]["stage"]: summary for summary in stage_summaries}
    early_metrics = stage_map["5"]["metrics"]
    full_metrics = stage_map["full"]["metrics"]
    early_centroids = stage_map["5"]["centroid_df"]
    full_centroids = stage_map["full"]["centroid_df"]

    early_scan_distance = float(
        early_centroids.loc[early_centroids["label"] == "SCAN", "distance_to_normal"].iloc[0]
    )
    full_scan_distance = float(
        full_centroids.loc[full_centroids["label"] == "SCAN", "distance_to_normal"].iloc[0]
    )

    lines = [
        "# Autoencoder 잠재공간 시각화",
        "",
        "## 개요",
        "",
        "이 문서는 anomaly benchmark에서 가장 성능이 좋았던 `Autoencoder`의 bottleneck 표현을 시각화한 결과다.",
        "학습된 모델의 가운데 hidden layer(`24차원`)를 잠재공간으로 보고, held-out test split에서 정상/비정상 flow가 어떻게 배치되는지 확인했다.",
        "",
        "## 방법",
        "",
        "- 사용 모델: `prediction/anomaly_benchmark/autoencoder/{5,full}/artifact.pkl`",
        "- 입력 데이터: anomaly benchmark의 test split",
        "- 잠재벡터: `hidden_sizes=(96, 24, 96)` 중 가운데 `24차원` activation",
        "- 전처리: artifact에 저장된 scaler 적용 후 잠재벡터를 다시 표준화",
        "- 시각화:",
        "  - PCA 2차원 투영: test 전체 row",
        "  - PCA 3차원 투영: label당 최대 2,500개 샘플 균형 추출 후 `png + html` 저장",
        "  - t-SNE 2차원 투영: label당 최대 2,500개 샘플 균형 추출",
        "  - t-SNE 3차원 투영: 같은 균형 샘플 기준 `png + html` 저장",
        "",
        "## 핵심 해석",
        "",
        f"- `5패킷` 잠재공간은 정상과 비정상이 비교적 또렷하게 갈린다. binary silhouette가 `{early_metrics['silhouette_binary']:.4f}`로 높고, 세 공격 모두 NORMAL centroid에서 멀리 떨어져 있다.",
        f"- `full` 잠재공간은 `GET_FLOOD`와 `CONNECTION_FLOOD`는 여전히 NORMAL과 분리되지만, `SCAN`은 NORMAL과 매우 가깝다. SCAN의 centroid distance가 `5패킷 {early_scan_distance:.4f}`에서 `full {full_scan_distance:.4f}`로 크게 줄었다.",
        f"- `full`의 binary silhouette는 `{full_metrics['silhouette_binary']:.4f}`로 낮다. 즉 전체 flow를 다 본다고 해서 bottleneck 공간이 더 깔끔한 군집을 만드는 것은 아니다.",
        "- 이 결과는 기존 성능표에서 `5패킷 Autoencoder`가 이미 매우 강하고, `full` 단계에서 가장 어려운 공격이 `SCAN`이었던 점과 방향이 맞는다.",
        "- 3D PCA/t-SNE를 보면 `5패킷`은 NORMAL 중심에서 공격군이 바깥으로 벌어지는 구조가 더 분명하고, `full`은 SCAN이 NORMAL 주변으로 다시 말려 들어오는 형태가 확인된다.",
        "",
        "## 정량 지표",
        "",
        f"- `5패킷` PCA 설명분산: `PC1={early_metrics['pca_explained_variance_ratio'][0]:.4f}`, `PC2={early_metrics['pca_explained_variance_ratio'][1]:.4f}`",
        f"- `5패킷` PCA 3D 설명분산 누적: `{sum(early_metrics['pca3d_explained_variance_ratio']):.4f}`",
        f"- `5패킷` silhouette: multiclass `{early_metrics['silhouette_multiclass']:.4f}`, binary `{early_metrics['silhouette_binary']:.4f}`",
        f"- `full` PCA 설명분산: `PC1={full_metrics['pca_explained_variance_ratio'][0]:.4f}`, `PC2={full_metrics['pca_explained_variance_ratio'][1]:.4f}`",
        f"- `full` PCA 3D 설명분산 누적: `{sum(full_metrics['pca3d_explained_variance_ratio']):.4f}`",
        f"- `full` silhouette: multiclass `{full_metrics['silhouette_multiclass']:.4f}`, binary `{full_metrics['silhouette_binary']:.4f}`",
        "",
        "## 잠재공간을 더 선명하게 만드는 방법",
        "",
        "- bottleneck 차원을 더 줄이는 것이 가장 먼저 볼 만하다. 현재 `24차원`은 복원에는 유리하지만 군집 분리에는 다소 넉넉해서, `8` 또는 `12` 차원으로 줄이면 NORMAL manifold가 더 조밀해질 가능성이 있다.",
        "- denoising autoencoder나 dropout/L1 sparsity를 주면 입력의 작은 흔들림에 덜 민감한 latent를 만들 수 있다. 특히 `full` 단계처럼 분포가 섞이는 경우 local noise를 줄이는 데 도움이 된다.",
        "- reconstruction loss만 쓰지 말고 latent center penalty를 같이 두는 것이 효과적이다. NORMAL latent를 하나의 중심 근처로 모으는 `center loss`나 `Deep SVDD`류 제약을 추가하면 군집 경계가 더 명확해진다.",
        "- anomaly score를 복원오차 하나로만 두지 말고 latent distance까지 합치는 방법이 좋다. 예를 들면 NORMAL latent centroid에 대한 Mahalanobis distance를 같이 쓰면 `SCAN`처럼 경계에 붙는 샘플을 더 잘 밀어낼 수 있다.",
        "- `full` 단계는 aggregate feature가 SCAN의 초기 구조를 희석하는 것이 문제로 보인다. 이 경우 모델보다 입력을 바꾸는 쪽이 더 효과적이라서, packet size/direction/IAT sequence를 직접 넣는 sequence autoencoder가 다음 우선순위다.",
        "",
        "### NORMAL centroid 거리",
        "",
        early_centroids.to_markdown(index=False),
        "",
        full_centroids.to_markdown(index=False),
        "",
        "## 시각화",
        "",
        "### 5패킷 잠재공간",
        "",
        "![5패킷 PCA](../prediction/anomaly_benchmark/autoencoder/5/latent_pca.png)",
        "",
        "![5패킷 t-SNE](../prediction/anomaly_benchmark/autoencoder/5/latent_tsne.png)",
        "",
        "![5패킷 centroid distance](../prediction/anomaly_benchmark/autoencoder/5/latent_centroid_distance.png)",
        "",
        "![5패킷 PCA 3D](../prediction/anomaly_benchmark/autoencoder/5/latent_pca_3d.png)",
        "",
        "[5패킷 PCA 3D HTML](../prediction/anomaly_benchmark/autoencoder/5/latent_pca_3d.html)",
        "",
        "![5패킷 t-SNE 3D](../prediction/anomaly_benchmark/autoencoder/5/latent_tsne_3d.png)",
        "",
        "[5패킷 t-SNE 3D HTML](../prediction/anomaly_benchmark/autoencoder/5/latent_tsne_3d.html)",
        "",
        "### 전체 flow 잠재공간",
        "",
        "![full PCA](../prediction/anomaly_benchmark/autoencoder/full/latent_pca.png)",
        "",
        "![full t-SNE](../prediction/anomaly_benchmark/autoencoder/full/latent_tsne.png)",
        "",
        "![full centroid distance](../prediction/anomaly_benchmark/autoencoder/full/latent_centroid_distance.png)",
        "",
        "![full PCA 3D](../prediction/anomaly_benchmark/autoencoder/full/latent_pca_3d.png)",
        "",
        "[full PCA 3D HTML](../prediction/anomaly_benchmark/autoencoder/full/latent_pca_3d.html)",
        "",
        "![full t-SNE 3D](../prediction/anomaly_benchmark/autoencoder/full/latent_tsne_3d.png)",
        "",
        "[full t-SNE 3D HTML](../prediction/anomaly_benchmark/autoencoder/full/latent_tsne_3d.html)",
        "",
        "## 산출물",
        "",
        "- `prediction/anomaly_benchmark/autoencoder/5/latent_embedding_test.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/5/latent_projection_pca.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/5/latent_projection_pca3d.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/5/latent_projection_pca3d_sample.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/5/latent_projection_tsne_sample.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/5/latent_projection_tsne3d_sample.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/full/latent_embedding_test.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/full/latent_projection_pca.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/full/latent_projection_pca3d.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/full/latent_projection_pca3d_sample.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/full/latent_projection_tsne_sample.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/full/latent_projection_tsne3d_sample.csv`",
        "- `prediction/anomaly_benchmark/autoencoder/{5,full}/latent_metrics.json`",
        "",
    ]

    DOC_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return DOC_PATH


def main() -> None:
    sns.set_theme(style="whitegrid")
    split_df = build_source_file_split()
    stage_summaries = [summarize_stage(stage_name, split_df) for stage_name in ["5", "full"]]
    doc_path = write_doc(stage_summaries)
    print(f"Latent visualization doc: {doc_path}")


if __name__ == "__main__":
    main()
