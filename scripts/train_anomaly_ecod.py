from __future__ import annotations

from anomaly_benchmark_common import run_single_model
from anomaly_benchmark_models import ECODDetector, ModelSpec


MODEL_SPEC = ModelSpec(
    name="ECOD",
    slug="ecod",
    use_scaler=False,
    builder=lambda: ECODDetector(),
    description=(
        "ECOD는 empirical CDF의 꼬리 확률을 이용하며, "
        "하나 이상의 feature에서 극단 꼬리 구간에 위치한 샘플에 높은 이상 점수를 준다."
    ),
)


if __name__ == "__main__":
    run_single_model(MODEL_SPEC)
