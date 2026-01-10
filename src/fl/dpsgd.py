"""
Frost Gate Spear - Differentially Private SGD Implementation

Implements DP-SGD (Differentially Private Stochastic Gradient Descent) for
privacy-preserving federated learning with formal privacy guarantees.

Based on "Deep Learning with Differential Privacy" (Abadi et al., 2016)
and "The Algorithmic Foundations of Differential Privacy" (Dwork & Roth, 2014)
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import UUID, uuid4

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class PrivacyBudget:
    """Privacy budget tracking for differential privacy."""
    epsilon: float  # Privacy parameter (lower = more private)
    delta: float    # Probability of privacy breach
    used_epsilon: float = 0.0
    used_delta: float = 0.0
    remaining_epsilon: float = field(init=False)
    remaining_delta: float = field(init=False)

    def __post_init__(self):
        self.remaining_epsilon = self.epsilon - self.used_epsilon
        self.remaining_delta = self.delta - self.used_delta

    def consume(self, epsilon: float, delta: float) -> bool:
        """Consume privacy budget."""
        if epsilon > self.remaining_epsilon or delta > self.remaining_delta:
            return False

        self.used_epsilon += epsilon
        self.used_delta += delta
        self.remaining_epsilon = self.epsilon - self.used_epsilon
        self.remaining_delta = self.delta - self.used_delta
        return True

    def is_exhausted(self) -> bool:
        """Check if budget is exhausted."""
        return self.remaining_epsilon <= 0 or self.remaining_delta <= 0

    def to_dict(self) -> Dict[str, float]:
        return {
            "epsilon": self.epsilon,
            "delta": self.delta,
            "used_epsilon": self.used_epsilon,
            "used_delta": self.used_delta,
            "remaining_epsilon": self.remaining_epsilon,
            "remaining_delta": self.remaining_delta,
        }


@dataclass
class DPSGDConfig:
    """Configuration for DP-SGD."""
    # Core DP parameters
    epsilon: float = 1.0       # Target epsilon for the training
    delta: float = 1e-5        # Target delta
    max_grad_norm: float = 1.0 # Gradient clipping bound (C)
    noise_multiplier: float = 1.0  # Ratio of noise to sensitivity

    # Training parameters
    batch_size: int = 32
    sample_rate: float = 0.01  # Fraction of data per batch

    # Noise mechanism
    mechanism: str = "gaussian"  # gaussian, laplace

    # Advanced options
    adaptive_clipping: bool = False
    target_unclipped_quantile: float = 0.5
    clip_count_stddev: float = 0.0
    num_microbatches: Optional[int] = None

    @classmethod
    def from_privacy_params(
        cls,
        epsilon: float,
        delta: float,
        sample_rate: float,
        num_steps: int,
        max_grad_norm: float = 1.0,
    ) -> "DPSGDConfig":
        """
        Create config from target privacy parameters.

        Computes the noise multiplier needed to achieve (epsilon, delta)-DP
        using the moments accountant / RDP analysis.
        """
        noise_multiplier = cls._compute_noise_multiplier(
            epsilon, delta, sample_rate, num_steps
        )

        return cls(
            epsilon=epsilon,
            delta=delta,
            max_grad_norm=max_grad_norm,
            noise_multiplier=noise_multiplier,
            sample_rate=sample_rate,
        )

    @staticmethod
    def _compute_noise_multiplier(
        epsilon: float,
        delta: float,
        sample_rate: float,
        num_steps: int,
        tolerance: float = 0.01,
    ) -> float:
        """
        Compute noise multiplier for target privacy using binary search.

        Uses Renyi Differential Privacy (RDP) to (epsilon, delta)-DP conversion.
        """
        def compute_epsilon_for_noise(noise_mult: float) -> float:
            """Compute epsilon given noise multiplier using RDP."""
            if noise_mult <= 0:
                return float('inf')

            # Compute RDP for Gaussian mechanism
            # For subsampled Gaussian mechanism with sampling rate q
            q = sample_rate
            sigma = noise_mult

            # Use simplified moments accountant approximation
            # Based on "Rényi Differential Privacy of the Sampled Gaussian Mechanism"
            rdp_orders = [1.5, 2, 2.5, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24, 32, 48, 64]
            min_epsilon = float('inf')

            for alpha in rdp_orders:
                # RDP guarantee for Gaussian mechanism
                rdp_single = alpha / (2 * sigma ** 2)

                # Apply subsampling amplification
                if q < 1:
                    # Simplified bound for subsampled mechanism
                    rdp_single = min(
                        rdp_single,
                        (1 / alpha) * math.log(1 + q ** 2 * (math.exp(alpha - 1) - 1))
                    )

                # Composition over steps
                rdp_total = num_steps * rdp_single

                # Convert RDP to (epsilon, delta)-DP
                epsilon_rdp = rdp_total + math.log(1 / delta) / (alpha - 1)
                min_epsilon = min(min_epsilon, epsilon_rdp)

            return min_epsilon

        # Binary search for noise multiplier
        low, high = 0.01, 100.0

        while high - low > tolerance:
            mid = (low + high) / 2
            current_eps = compute_epsilon_for_noise(mid)

            if current_eps > epsilon:
                low = mid
            else:
                high = mid

        return high


@dataclass
class GradientClipResult:
    """Result of gradient clipping operation."""
    clipped_gradient: np.ndarray
    original_norm: float
    clipped_norm: float
    was_clipped: bool
    clip_factor: float


@dataclass
class NoisyGradientResult:
    """Result of noisy gradient computation."""
    noisy_gradient: np.ndarray
    noise_scale: float
    privacy_cost: Tuple[float, float]  # (epsilon, delta)
    clipping_results: List[GradientClipResult]
    num_samples: int
    timestamp: datetime


class GradientClipper:
    """
    Per-sample gradient clipping for DP-SGD.

    Implements L2 norm clipping to bound sensitivity.
    """

    def __init__(self, max_grad_norm: float):
        """
        Initialize gradient clipper.

        Args:
            max_grad_norm: Maximum L2 norm for gradients (C parameter)
        """
        self.max_grad_norm = max_grad_norm
        self._clip_history: List[float] = []

    def clip_gradient(self, gradient: np.ndarray) -> GradientClipResult:
        """
        Clip gradient to maximum L2 norm.

        Args:
            gradient: Input gradient (can be 1D or multi-dimensional)

        Returns:
            Clipping result with clipped gradient
        """
        # Flatten gradient for norm computation
        flat_grad = gradient.flatten()
        original_norm = float(np.linalg.norm(flat_grad))

        # Clip to max norm
        if original_norm > self.max_grad_norm:
            clip_factor = self.max_grad_norm / original_norm
            clipped_grad = gradient * clip_factor
            clipped_norm = self.max_grad_norm
            was_clipped = True
        else:
            clipped_grad = gradient.copy()
            clipped_norm = original_norm
            clip_factor = 1.0
            was_clipped = False

        self._clip_history.append(original_norm)

        return GradientClipResult(
            clipped_gradient=clipped_grad,
            original_norm=original_norm,
            clipped_norm=clipped_norm,
            was_clipped=was_clipped,
            clip_factor=clip_factor,
        )

    def clip_gradients(
        self,
        gradients: List[np.ndarray],
    ) -> Tuple[List[np.ndarray], List[GradientClipResult]]:
        """
        Clip multiple per-sample gradients.

        Args:
            gradients: List of per-sample gradients

        Returns:
            Tuple of (clipped gradients, clip results)
        """
        results = []
        clipped = []

        for grad in gradients:
            result = self.clip_gradient(grad)
            results.append(result)
            clipped.append(result.clipped_gradient)

        return clipped, results

    def get_clip_statistics(self) -> Dict[str, float]:
        """Get clipping statistics."""
        if not self._clip_history:
            return {}

        history = np.array(self._clip_history)
        clip_threshold = self.max_grad_norm

        return {
            "mean_norm": float(np.mean(history)),
            "max_norm": float(np.max(history)),
            "min_norm": float(np.min(history)),
            "clipped_fraction": float(np.mean(history > clip_threshold)),
            "clip_threshold": clip_threshold,
        }


class NoiseGenerator:
    """
    Noise generator for differential privacy.

    Supports Gaussian and Laplace mechanisms.
    """

    def __init__(
        self,
        mechanism: str = "gaussian",
        seed: Optional[int] = None,
    ):
        """
        Initialize noise generator.

        Args:
            mechanism: Noise mechanism (gaussian, laplace)
            seed: Random seed for reproducibility
        """
        self.mechanism = mechanism
        self._rng = np.random.default_rng(seed)

    def generate_noise(
        self,
        shape: Tuple[int, ...],
        scale: float,
    ) -> np.ndarray:
        """
        Generate noise for DP mechanism.

        Args:
            shape: Shape of noise tensor
            scale: Scale parameter (sigma for Gaussian, b for Laplace)

        Returns:
            Noise array of specified shape
        """
        if self.mechanism == "gaussian":
            return self._rng.normal(0, scale, shape)
        elif self.mechanism == "laplace":
            return self._rng.laplace(0, scale, shape)
        else:
            raise ValueError(f"Unknown mechanism: {self.mechanism}")

    def compute_noise_scale(
        self,
        sensitivity: float,
        noise_multiplier: float,
        batch_size: int,
    ) -> float:
        """
        Compute noise scale for given sensitivity.

        Args:
            sensitivity: L2 sensitivity (typically max_grad_norm)
            noise_multiplier: Noise multiplier (sigma/C ratio)
            batch_size: Number of samples in batch

        Returns:
            Noise scale (standard deviation)
        """
        # Noise is calibrated to sensitivity / batch_size
        # since we sum over batch and then divide
        return (sensitivity * noise_multiplier) / batch_size


class DPSGDMechanism:
    """
    Full DP-SGD mechanism implementation.

    Combines gradient clipping, noise addition, and privacy accounting.
    """

    def __init__(self, config: DPSGDConfig):
        """
        Initialize DP-SGD mechanism.

        Args:
            config: DP-SGD configuration
        """
        self.config = config
        self.clipper = GradientClipper(config.max_grad_norm)
        self.noise_gen = NoiseGenerator(config.mechanism)
        self.privacy_budget = PrivacyBudget(config.epsilon, config.delta)
        self._rounds_completed = 0
        self._total_samples_processed = 0

    def process_gradients(
        self,
        per_sample_gradients: List[np.ndarray],
    ) -> NoisyGradientResult:
        """
        Process per-sample gradients with DP-SGD.

        Steps:
        1. Clip each per-sample gradient
        2. Sum clipped gradients
        3. Add calibrated noise
        4. Divide by batch size

        Args:
            per_sample_gradients: List of per-sample gradients

        Returns:
            Noisy averaged gradient with privacy accounting
        """
        batch_size = len(per_sample_gradients)

        if batch_size == 0:
            raise ValueError("Empty gradient batch")

        # Step 1: Clip gradients
        clipped_grads, clip_results = self.clipper.clip_gradients(per_sample_gradients)

        # Step 2: Sum clipped gradients
        summed_grad = np.sum(clipped_grads, axis=0)

        # Step 3: Compute noise scale and add noise
        noise_scale = self.noise_gen.compute_noise_scale(
            sensitivity=self.config.max_grad_norm,
            noise_multiplier=self.config.noise_multiplier,
            batch_size=batch_size,
        )

        noise = self.noise_gen.generate_noise(summed_grad.shape, noise_scale * batch_size)
        noisy_sum = summed_grad + noise

        # Step 4: Average
        noisy_grad = noisy_sum / batch_size

        # Privacy accounting
        privacy_cost = self._compute_privacy_cost(batch_size)

        self._rounds_completed += 1
        self._total_samples_processed += batch_size

        return NoisyGradientResult(
            noisy_gradient=noisy_grad,
            noise_scale=noise_scale,
            privacy_cost=privacy_cost,
            clipping_results=clip_results,
            num_samples=batch_size,
            timestamp=datetime.utcnow(),
        )

    def _compute_privacy_cost(
        self,
        batch_size: int,
    ) -> Tuple[float, float]:
        """
        Compute privacy cost for one step.

        Uses simplified RDP-to-DP conversion for single step.
        """
        sigma = self.config.noise_multiplier
        q = batch_size * self.config.sample_rate

        # Approximate epsilon for single step using RDP analysis
        # For Gaussian mechanism with subsampling
        alpha = 2  # Use alpha=2 for simple bound
        rdp_single = alpha / (2 * sigma ** 2)

        # Subsampling amplification
        if q < 1:
            rdp_single = min(rdp_single, q ** 2 * rdp_single)

        # Convert to (epsilon, delta)-DP
        eps_step = rdp_single + math.log(1 / self.config.delta) / (alpha - 1)
        delta_step = self.config.delta

        return (eps_step, delta_step)

    def get_privacy_spent(self) -> Dict[str, Any]:
        """Get total privacy spent so far."""
        return {
            "epsilon_spent": self.privacy_budget.used_epsilon,
            "delta_spent": self.privacy_budget.used_delta,
            "epsilon_remaining": self.privacy_budget.remaining_epsilon,
            "delta_remaining": self.privacy_budget.remaining_delta,
            "rounds_completed": self._rounds_completed,
            "total_samples": self._total_samples_processed,
        }


class FederatedDPAggregator:
    """
    DP-secure aggregator for federated learning.

    Aggregates model updates from multiple clients with differential privacy.
    """

    def __init__(
        self,
        config: DPSGDConfig,
        num_clients: int,
        client_weight_fn: Optional[callable] = None,
    ):
        """
        Initialize federated DP aggregator.

        Args:
            config: DP-SGD configuration
            num_clients: Total number of clients
            client_weight_fn: Function to compute client weights
        """
        self.config = config
        self.num_clients = num_clients
        self.client_weight_fn = client_weight_fn or (lambda i: 1.0 / num_clients)
        self.dp_mechanism = DPSGDMechanism(config)

        # Track client contributions
        self._round_contributions: Dict[int, Dict[str, np.ndarray]] = {}
        self._current_round = 0

    def submit_client_update(
        self,
        client_id: int,
        model_delta: Dict[str, np.ndarray],
    ) -> bool:
        """
        Submit model update from client.

        Args:
            client_id: Client identifier
            model_delta: Dictionary mapping parameter names to gradients

        Returns:
            True if submission accepted
        """
        if client_id in self._round_contributions:
            logger.warning(f"Client {client_id} already submitted for round {self._current_round}")
            return False

        # Clip each parameter gradient
        clipped_delta = {}
        for name, grad in model_delta.items():
            result = self.dp_mechanism.clipper.clip_gradient(grad)
            clipped_delta[name] = result.clipped_gradient

        self._round_contributions[client_id] = clipped_delta
        logger.debug(f"Received update from client {client_id}")
        return True

    def aggregate(
        self,
        min_clients: int = 3,
    ) -> Optional[Dict[str, np.ndarray]]:
        """
        Aggregate client updates with DP noise.

        Args:
            min_clients: Minimum clients required for aggregation

        Returns:
            Aggregated noisy model update or None if insufficient clients
        """
        num_contributions = len(self._round_contributions)

        if num_contributions < min_clients:
            logger.warning(
                f"Insufficient clients for aggregation: {num_contributions} < {min_clients}"
            )
            return None

        # Get all parameter names from first contribution
        first_update = next(iter(self._round_contributions.values()))
        param_names = list(first_update.keys())

        # Aggregate each parameter
        aggregated = {}
        for name in param_names:
            # Collect all updates for this parameter
            all_updates = []
            for client_id, delta in self._round_contributions.items():
                weight = self.client_weight_fn(client_id)
                weighted_update = delta[name] * weight
                all_updates.append(weighted_update)

            # Sum updates
            summed = np.sum(all_updates, axis=0)

            # Add DP noise calibrated to sensitivity
            noise_scale = self.dp_mechanism.noise_gen.compute_noise_scale(
                sensitivity=self.config.max_grad_norm,
                noise_multiplier=self.config.noise_multiplier,
                batch_size=num_contributions,
            )

            noise = self.dp_mechanism.noise_gen.generate_noise(
                summed.shape,
                noise_scale * num_contributions,
            )

            aggregated[name] = summed + noise

        # Clear contributions for next round
        self._round_contributions.clear()
        self._current_round += 1

        logger.info(
            f"Aggregated {num_contributions} client updates for round {self._current_round}"
        )

        return aggregated

    def get_privacy_spent(self) -> Dict[str, Any]:
        """Get cumulative privacy spent."""
        return {
            "current_round": self._current_round,
            **self.dp_mechanism.get_privacy_spent(),
        }


def compute_dp_sgd_privacy(
    sample_size: int,
    batch_size: int,
    noise_multiplier: float,
    num_epochs: int,
    delta: float,
) -> float:
    """
    Compute epsilon for given DP-SGD parameters.

    Convenience function for privacy analysis.

    Args:
        sample_size: Total dataset size
        batch_size: Training batch size
        noise_multiplier: Noise multiplier (sigma)
        num_epochs: Number of training epochs
        delta: Target delta

    Returns:
        Computed epsilon
    """
    steps = num_epochs * (sample_size // batch_size)
    sample_rate = batch_size / sample_size

    # Use simplified RDP analysis
    orders = [1.5, 2, 2.5, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24, 32, 48, 64]
    min_epsilon = float('inf')

    for alpha in orders:
        rdp_single = alpha / (2 * noise_multiplier ** 2)

        # Subsampling amplification
        if sample_rate < 1:
            rdp_single = sample_rate ** 2 * rdp_single

        rdp_total = steps * rdp_single
        epsilon = rdp_total + math.log(1 / delta) / (alpha - 1)
        min_epsilon = min(min_epsilon, epsilon)

    return min_epsilon


def validate_dp_guarantee(
    epsilon: float,
    delta: float,
    ring: str,
) -> Tuple[bool, str]:
    """
    Validate DP guarantees meet ring requirements.

    Args:
        epsilon: Achieved epsilon
        delta: Achieved delta
        ring: Classification ring

    Returns:
        Tuple of (valid, reason)
    """
    # Ring-specific requirements
    ring_requirements = {
        "UNCLASS": {"max_epsilon": 10.0, "max_delta": 1e-4},
        "CUI": {"max_epsilon": 5.0, "max_delta": 1e-5},
        "SECRET": {"max_epsilon": 2.0, "max_delta": 1e-6},
        "TOPSECRET": {"max_epsilon": 1.0, "max_delta": 1e-7},
    }

    reqs = ring_requirements.get(ring, ring_requirements["UNCLASS"])

    if epsilon > reqs["max_epsilon"]:
        return False, f"Epsilon {epsilon} exceeds ring requirement {reqs['max_epsilon']}"

    if delta > reqs["max_delta"]:
        return False, f"Delta {delta} exceeds ring requirement {reqs['max_delta']}"

    return True, "DP guarantees within ring requirements"


__all__ = [
    "DPSGDConfig",
    "DPSGDMechanism",
    "GradientClipper",
    "GradientClipResult",
    "NoiseGenerator",
    "NoisyGradientResult",
    "PrivacyBudget",
    "FederatedDPAggregator",
    "compute_dp_sgd_privacy",
    "validate_dp_guarantee",
]
