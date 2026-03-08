from __future__ import annotations

from anomaly_benchmark_common import generate_comparison_artifacts, run_single_model
from train_anomaly_autoencoder import MODEL_SPEC as AUTOENCODER_SPEC
from train_anomaly_ecod import MODEL_SPEC as ECOD_SPEC
from train_anomaly_hbos import MODEL_SPEC as HBOS_SPEC
from train_anomaly_isolation_forest import MODEL_SPEC as ISOLATION_FOREST_SPEC
from train_anomaly_pca import MODEL_SPEC as PCA_SPEC


MODEL_SPECS = [
    ISOLATION_FOREST_SPEC,
    HBOS_SPEC,
    ECOD_SPEC,
    PCA_SPEC,
    AUTOENCODER_SPEC,
]


def main() -> None:
    results = []
    for spec in MODEL_SPECS:
        print(f"\nRunning {spec.name}...")
        results.append(run_single_model(spec))

    doc_path = generate_comparison_artifacts(results)
    print("\nBenchmark complete.")
    print(f"Comparison doc: {doc_path}")


if __name__ == "__main__":
    main()
