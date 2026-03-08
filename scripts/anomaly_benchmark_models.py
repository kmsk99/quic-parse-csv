from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor


class IsolationForestDetector:
    def __init__(self, random_state: int) -> None:
        self.model = IsolationForest(
            n_estimators=300,
            contamination="auto",
            random_state=random_state,
            n_jobs=-1,
        )

    def fit(self, x: np.ndarray) -> "IsolationForestDetector":
        self.model.fit(x)
        return self

    def decision_function(self, x: np.ndarray) -> np.ndarray:
        return -self.model.score_samples(x)

    def metadata(self) -> dict[str, float | int | str]:
        return {
            "backend": "sklearn",
            "n_estimators": 300,
        }


class HBOSDetector:
    def __init__(self, max_bins: int = 20, alpha: float = 1e-6) -> None:
        self.max_bins = max_bins
        self.alpha = alpha
        self.histograms: list[tuple[np.ndarray, np.ndarray]] = []

    def fit(self, x: np.ndarray) -> "HBOSDetector":
        self.histograms = []
        n_samples = x.shape[0]
        n_bins = min(self.max_bins, max(5, int(np.sqrt(max(n_samples, 2)))))

        for column in range(x.shape[1]):
            values = x[:, column]
            finite_values = values[np.isfinite(values)]
            if finite_values.size == 0:
                edges = np.array([-0.5, 0.5], dtype=float)
                probs = np.array([1.0], dtype=float)
            elif np.allclose(finite_values, finite_values[0]):
                center = float(finite_values[0])
                edges = np.array([center - 0.5, center + 0.5], dtype=float)
                probs = np.array([1.0], dtype=float)
            else:
                counts, edges = np.histogram(finite_values, bins=n_bins)
                probs = counts.astype(float) / max(finite_values.size, 1)
                probs = np.clip(probs, self.alpha, None)
                probs = probs / probs.sum()
            self.histograms.append((edges, probs))

        return self

    def decision_function(self, x: np.ndarray) -> np.ndarray:
        total_scores = np.zeros(x.shape[0], dtype=float)
        for column, (edges, probs) in enumerate(self.histograms):
            values = x[:, column]
            bin_indices = np.searchsorted(edges, values, side="right") - 1
            bin_indices = np.clip(bin_indices, 0, len(probs) - 1)
            total_scores += -np.log(np.clip(probs[bin_indices], self.alpha, None))
        return total_scores

    def metadata(self) -> dict[str, float | int | str]:
        return {
            "backend": "custom",
            "max_bins": self.max_bins,
        }


class ECODDetector:
    def __init__(self, epsilon: float = 1e-12) -> None:
        self.epsilon = epsilon
        self.sorted_columns: list[np.ndarray] = []
        self.n_train = 0

    def fit(self, x: np.ndarray) -> "ECODDetector":
        self.sorted_columns = [np.sort(x[:, column]) for column in range(x.shape[1])]
        self.n_train = x.shape[0]
        return self

    def decision_function(self, x: np.ndarray) -> np.ndarray:
        scores = np.zeros(x.shape[0], dtype=float)
        denom = self.n_train + 1.0

        for column, sorted_values in enumerate(self.sorted_columns):
            values = x[:, column]
            left_rank = np.searchsorted(sorted_values, values, side="right")
            right_rank = self.n_train - np.searchsorted(sorted_values, values, side="left") + 1

            left_prob = np.clip(left_rank / denom, self.epsilon, 1.0)
            right_prob = np.clip(right_rank / denom, self.epsilon, 1.0)
            tail_score = np.maximum(-np.log(left_prob), -np.log(right_prob))
            scores += tail_score

        return scores

    def metadata(self) -> dict[str, float | int | str]:
        return {
            "backend": "custom",
            "epsilon": self.epsilon,
        }


class PCAReconstructionDetector:
    def __init__(self, explained_variance: float = 0.95) -> None:
        self.explained_variance = explained_variance
        self.model = PCA(n_components=explained_variance, svd_solver="full")

    def fit(self, x: np.ndarray) -> "PCAReconstructionDetector":
        self.model.fit(x)
        return self

    def decision_function(self, x: np.ndarray) -> np.ndarray:
        reconstructed = self.model.inverse_transform(self.model.transform(x))
        return np.mean((x - reconstructed) ** 2, axis=1)

    def metadata(self) -> dict[str, float | int | str]:
        return {
            "backend": "sklearn",
            "explained_variance": self.explained_variance,
            "n_components_selected": int(self.model.n_components_),
        }


class AutoencoderDetector:
    def __init__(self, random_state: int, hidden_sizes: tuple[int, int, int] = (96, 24, 96)) -> None:
        self.hidden_sizes = hidden_sizes
        self.model = MLPRegressor(
            hidden_layer_sizes=hidden_sizes,
            activation="relu",
            solver="adam",
            learning_rate_init=1e-3,
            max_iter=300,
            random_state=random_state,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=12,
        )

    def fit(self, x: np.ndarray) -> "AutoencoderDetector":
        self.model.fit(x, x)
        return self

    def decision_function(self, x: np.ndarray) -> np.ndarray:
        reconstructed = self.model.predict(x)
        return np.mean((x - reconstructed) ** 2, axis=1)

    def encode(self, x: np.ndarray) -> np.ndarray:
        """Returns the bottleneck activation of the encoder half."""
        hidden = x
        encoder_layers = len(self.hidden_sizes) // 2 + 1
        for layer_index in range(encoder_layers):
            hidden = hidden @ self.model.coefs_[layer_index] + self.model.intercepts_[layer_index]
            hidden = np.maximum(hidden, 0.0)
        return hidden

    def metadata(self) -> dict[str, float | int | str]:
        return {
            "backend": "sklearn-mlp",
            "hidden_sizes": list(self.hidden_sizes),
            "iterations": int(self.model.n_iter_),
            "final_loss": float(self.model.loss_),
        }


@dataclass(frozen=True)
class ModelSpec:
    name: str
    slug: str
    use_scaler: bool
    builder: callable
    description: str
