from __future__ import annotations

from anomaly_benchmark_common import run_single_model
from anomaly_benchmark_models import HBOSDetector, ModelSpec


MODEL_SPEC = ModelSpec(
    name="HBOS",
    slug="hbos",
    use_scaler=False,
    builder=lambda: HBOSDetector(max_bins=20),
    description=(
        "HBOS는 각 feature를 독립적인 histogram으로 모델링하고, "
        "밀도가 낮은 bin에 들어가는 샘플에 더 큰 이상 점수를 부여한다."
    ),
)


if __name__ == "__main__":
    run_single_model(MODEL_SPEC)
