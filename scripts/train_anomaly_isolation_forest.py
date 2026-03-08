from __future__ import annotations

from anomaly_benchmark_common import RANDOM_SEED, run_single_model
from anomaly_benchmark_models import IsolationForestDetector, ModelSpec


MODEL_SPEC = ModelSpec(
    name="IsolationForest",
    slug="isolation_forest",
    use_scaler=True,
    builder=lambda: IsolationForestDetector(random_state=RANDOM_SEED),
    description=(
        "Isolation Forest는 특징 공간을 재귀적으로 분할하면서 이상치를 분리한다. "
        "더 적은 분할로 쉽게 고립되는 샘플일수록 높은 이상 점수를 받는다."
    ),
)


if __name__ == "__main__":
    run_single_model(MODEL_SPEC)
