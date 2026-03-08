from __future__ import annotations

from anomaly_benchmark_common import RANDOM_SEED, run_single_model
from anomaly_benchmark_models import AutoencoderDetector, ModelSpec


MODEL_SPEC = ModelSpec(
    name="Autoencoder",
    slug="autoencoder",
    use_scaler=True,
    builder=lambda: AutoencoderDetector(random_state=RANDOM_SEED),
    description=(
        "Autoencoder는 정상 트래픽을 복원하도록 학습된 작은 MLP이며, "
        "복원 오차가 큰 샘플을 이상으로 간주한다."
    ),
)


if __name__ == "__main__":
    run_single_model(MODEL_SPEC)
