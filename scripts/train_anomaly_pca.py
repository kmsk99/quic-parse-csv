from __future__ import annotations

from anomaly_benchmark_common import run_single_model
from anomaly_benchmark_models import ModelSpec, PCAReconstructionDetector


MODEL_SPEC = ModelSpec(
    name="PCAReconstruction",
    slug="pca_reconstruction",
    use_scaler=True,
    builder=lambda: PCAReconstructionDetector(explained_variance=0.95),
    description=(
        "PCA reconstruction은 정상 트래픽으로부터 저차원 부분공간을 학습하고, "
        "복원 오차를 이상 점수로 사용한다."
    ),
)


if __name__ == "__main__":
    run_single_model(MODEL_SPEC)
