"""
Frost Gate Spear - Target Impact Estimator (TIE)

ML-powered impact estimation and tracking for mission operations.
Supports both rule-based and neural network prediction models.
"""

import asyncio
import hashlib
import json
import logging
import pickle
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import numpy as np

from ..core.config import Config
from ..core.exceptions import BlastRadiusExceededError

logger = logging.getLogger(__name__)


@dataclass
class ModelInfo:
    """Information about loaded ML model."""
    model_id: str
    model_version: str
    model_type: str
    model_hash: str
    loaded_at: datetime
    input_features: List[str]
    output_classes: List[str]
    performance_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class ImpactEstimate:
    """Impact estimation result."""
    score: float  # 0-100 scale
    confidence: float  # 0-1 confidence in estimate
    breakdown: Dict[str, float]
    exceeds_blast_radius: bool
    blast_radius_cap: float
    timestamp: datetime
    methodology: str


@dataclass
class ImpactFactors:
    """Factors contributing to impact score."""
    target_criticality: float = 0.0
    action_severity: float = 0.0
    scope_breadth: float = 0.0
    persistence_depth: float = 0.0
    data_sensitivity: float = 0.0
    service_disruption: float = 0.0
    detection_likelihood: float = 0.0


class ImpactPredictor:
    """
    Neural network-based impact predictor.

    Uses a trained model to predict impact scores based on:
    - Target features (type, criticality, network position)
    - Action features (technique, severity, scope)
    - Context features (time, cumulative impact, detection state)
    """

    def __init__(self, model_path: Optional[Path] = None):
        """Initialize predictor."""
        self.model = None
        self.scaler = None
        self.model_info: Optional[ModelInfo] = None
        self._model_path = model_path

    async def load(self) -> bool:
        """Load trained model from disk."""
        if not self._model_path or not self._model_path.exists():
            logger.info("No ML model path configured, using fallback prediction")
            return False

        try:
            # Try loading PyTorch model
            if self._model_path.suffix == ".pt":
                return await self._load_pytorch_model()
            # Try loading sklearn model
            elif self._model_path.suffix == ".pkl":
                return await self._load_sklearn_model()
            # Try loading ONNX model
            elif self._model_path.suffix == ".onnx":
                return await self._load_onnx_model()
            else:
                logger.warning(f"Unsupported model format: {self._model_path.suffix}")
                return False

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    async def _load_pytorch_model(self) -> bool:
        """Load PyTorch model."""
        try:
            import torch

            self.model = torch.jit.load(str(self._model_path))
            self.model.eval()

            # Load model metadata
            meta_path = self._model_path.with_suffix(".json")
            if meta_path.exists():
                with open(meta_path) as f:
                    meta = json.load(f)
                self.model_info = ModelInfo(
                    model_id=meta.get("model_id", "unknown"),
                    model_version=meta.get("version", "1.0"),
                    model_type="pytorch",
                    model_hash=self._compute_model_hash(),
                    loaded_at=datetime.utcnow(),
                    input_features=meta.get("input_features", []),
                    output_classes=meta.get("output_classes", []),
                    performance_metrics=meta.get("metrics", {}),
                )

            logger.info(f"Loaded PyTorch model: {self._model_path}")
            return True

        except ImportError:
            logger.warning("PyTorch not available")
            return False

    async def _load_sklearn_model(self) -> bool:
        """Load scikit-learn model."""
        try:
            with open(self._model_path, "rb") as f:
                data = pickle.load(f)

            if isinstance(data, dict):
                self.model = data.get("model")
                self.scaler = data.get("scaler")
                self.model_info = ModelInfo(
                    model_id=data.get("model_id", "sklearn_impact"),
                    model_version=data.get("version", "1.0"),
                    model_type="sklearn",
                    model_hash=self._compute_model_hash(),
                    loaded_at=datetime.utcnow(),
                    input_features=data.get("features", []),
                    output_classes=["impact_score"],
                    performance_metrics=data.get("metrics", {}),
                )
            else:
                self.model = data

            logger.info(f"Loaded sklearn model: {self._model_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to load sklearn model: {e}")
            return False

    async def _load_onnx_model(self) -> bool:
        """Load ONNX model for inference."""
        try:
            import onnxruntime as ort

            self.model = ort.InferenceSession(str(self._model_path))

            # Get input/output names
            input_names = [inp.name for inp in self.model.get_inputs()]
            output_names = [out.name for out in self.model.get_outputs()]

            self.model_info = ModelInfo(
                model_id="onnx_impact",
                model_version="1.0",
                model_type="onnx",
                model_hash=self._compute_model_hash(),
                loaded_at=datetime.utcnow(),
                input_features=input_names,
                output_classes=output_names,
            )

            logger.info(f"Loaded ONNX model: {self._model_path}")
            return True

        except ImportError:
            logger.warning("ONNX Runtime not available")
            return False

    def _compute_model_hash(self) -> str:
        """Compute hash of model file."""
        if not self._model_path or not self._model_path.exists():
            return ""

        content = self._model_path.read_bytes()
        return f"sha256:{hashlib.sha256(content).hexdigest()}"

    def predict(self, features: np.ndarray) -> Tuple[float, float]:
        """
        Predict impact score from features.

        Args:
            features: Input feature vector

        Returns:
            Tuple of (predicted_score, confidence)
        """
        if self.model is None:
            return self._fallback_predict(features)

        try:
            # Scale features if scaler available
            if self.scaler is not None:
                features = self.scaler.transform(features.reshape(1, -1))

            # Predict based on model type
            if self.model_info and self.model_info.model_type == "pytorch":
                return self._predict_pytorch(features)
            elif self.model_info and self.model_info.model_type == "onnx":
                return self._predict_onnx(features)
            else:
                return self._predict_sklearn(features)

        except Exception as e:
            logger.warning(f"Model prediction failed: {e}, using fallback")
            return self._fallback_predict(features)

    def _predict_pytorch(self, features: np.ndarray) -> Tuple[float, float]:
        """Predict using PyTorch model."""
        import torch

        with torch.no_grad():
            x = torch.tensor(features, dtype=torch.float32)
            output = self.model(x)

            if isinstance(output, tuple):
                score, confidence = output
                return float(score.item()), float(confidence.item())
            else:
                return float(output.item()), 0.8

    def _predict_sklearn(self, features: np.ndarray) -> Tuple[float, float]:
        """Predict using sklearn model."""
        prediction = self.model.predict(features.reshape(1, -1))

        # Try to get prediction probability
        confidence = 0.8
        if hasattr(self.model, "predict_proba"):
            try:
                proba = self.model.predict_proba(features.reshape(1, -1))
                confidence = float(np.max(proba))
            except Exception:
                pass

        return float(prediction[0]), confidence

    def _predict_onnx(self, features: np.ndarray) -> Tuple[float, float]:
        """Predict using ONNX model."""
        input_name = self.model.get_inputs()[0].name
        inputs = {input_name: features.astype(np.float32).reshape(1, -1)}

        outputs = self.model.run(None, inputs)
        score = float(outputs[0][0])
        confidence = float(outputs[1][0]) if len(outputs) > 1 else 0.8

        return score, confidence

    def _fallback_predict(self, features: np.ndarray) -> Tuple[float, float]:
        """Fallback prediction using simple heuristics."""
        # Use feature values as weights for simple prediction
        if len(features) >= 2:
            score = float(features[0] * 50 + features[1] * 30)
        else:
            score = float(np.mean(features) * 50)

        return min(max(score, 0), 100), 0.5


class TargetImpactEstimator:
    """
    Target Impact Estimator (TIE).

    Estimates operational impact including:
    - Target criticality assessment
    - Action severity scoring
    - Blast radius prediction
    - Cumulative impact tracking
    - ML-based impact prediction with model loading
    """

    def __init__(self, config: Config):
        """Initialize TIE."""
        self.config = config
        self._predictor: Optional[ImpactPredictor] = None
        self._model_loaded = False
        self._criticality_map: Dict[str, float] = {}
        self._action_severity: Dict[str, float] = {}

        # For backwards compatibility
        self._model = None

    async def start(self) -> None:
        """Start the TIE with ML model loading."""
        logger.info("Starting Target Impact Estimator...")
        await self._load_models()
        self._initialize_scoring_maps()
        logger.info("Target Impact Estimator started")

    async def stop(self) -> None:
        """Stop the TIE."""
        logger.info("Stopping Target Impact Estimator...")
        self._predictor = None
        self._model_loaded = False

    async def _load_models(self) -> None:
        """Load ML models for impact prediction."""
        if not self.config.tie.enable_ml_predictions:
            logger.info("ML predictions disabled in config")
            return

        # Get model path from config or use default
        model_path = getattr(self.config.tie, "model_path", None)
        if model_path:
            model_path = Path(model_path)
        else:
            # Try default locations
            default_paths = [
                Path("models/tie_impact_model.pt"),
                Path("models/tie_impact_model.pkl"),
                Path("models/tie_impact_model.onnx"),
            ]
            for path in default_paths:
                if path.exists():
                    model_path = path
                    break

        if model_path:
            self._predictor = ImpactPredictor(model_path)
            self._model_loaded = await self._predictor.load()

            if self._model_loaded:
                logger.info(
                    f"ML model loaded: {self._predictor.model_info.model_id} "
                    f"v{self._predictor.model_info.model_version}"
                )
                # Set _model for backwards compatibility
                self._model = self._predictor.model
            else:
                logger.warning("Failed to load ML model, using rule-based estimation")
        else:
            logger.info("No ML model found, using rule-based estimation")

    def _initialize_scoring_maps(self) -> None:
        """Initialize criticality and severity scoring maps."""
        # Target criticality scores (0-1)
        self._criticality_map = {
            "domain_controller": 1.0,
            "pki_server": 0.95,
            "database_server": 0.9,
            "file_server": 0.7,
            "web_server": 0.6,
            "workstation": 0.3,
            "printer": 0.1,
            "iot_device": 0.2,
            "scada": 1.0,
            "ics": 0.95,
            "medical_device": 1.0,
            "safety_system": 1.0,
        }

        # Action severity scores (0-1)
        self._action_severity = {
            "reconnaissance": 0.1,
            "vulnerability_scan": 0.2,
            "exploitation": 0.6,
            "credential_access": 0.7,
            "lateral_movement": 0.7,
            "privilege_escalation": 0.8,
            "persistence": 0.7,
            "data_exfiltration": 0.9,
            "data_destruction": 1.0,
            "service_disruption": 0.9,
            "ransomware": 1.0,
        }

    async def estimate_impact(self, mission: Any) -> ImpactEstimate:
        """
        Estimate overall mission impact.

        Args:
            mission: Mission to estimate impact for

        Returns:
            Impact estimate
        """
        factors = await self._calculate_factors(mission)
        score = self._compute_score(factors)

        blast_radius_cap = self._get_blast_radius_cap(mission)
        exceeds = score > blast_radius_cap

        estimate = ImpactEstimate(
            score=score,
            confidence=self._compute_confidence(factors),
            breakdown={
                "target_criticality": factors.target_criticality * 20,
                "action_severity": factors.action_severity * 25,
                "scope_breadth": factors.scope_breadth * 15,
                "persistence_depth": factors.persistence_depth * 15,
                "data_sensitivity": factors.data_sensitivity * 15,
                "service_disruption": factors.service_disruption * 10,
            },
            exceeds_blast_radius=exceeds,
            blast_radius_cap=blast_radius_cap,
            timestamp=datetime.utcnow(),
            methodology="weighted_factors_v1",
        )

        if exceeds:
            logger.warning(
                f"Impact estimate {score} exceeds blast radius cap {blast_radius_cap}"
            )

        return estimate

    async def estimate_action_impact(
        self,
        action: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> ImpactEstimate:
        """
        Estimate impact of a single action.

        Args:
            action: Action to estimate
            context: Additional context

        Returns:
            Impact estimate
        """
        context = context or {}

        # Get target criticality
        target = action.get("target", {})
        target_type = target.get("type", "unknown")
        criticality = self._criticality_map.get(target_type, 0.5)

        # Get action severity
        action_type = action.get("type", "unknown")
        severity = self._action_severity.get(action_type, 0.5)

        # Compute score
        base_score = (criticality * 0.4 + severity * 0.6) * 100

        # Apply modifiers
        if action.get("destructive"):
            base_score *= 1.5

        if target.get("criticality") == "high":
            base_score *= 1.3

        score = min(base_score, 100)

        blast_radius_cap = context.get("blast_radius_cap", 100)

        return ImpactEstimate(
            score=score,
            confidence=0.8,
            breakdown={
                "target_criticality": criticality * 40,
                "action_severity": severity * 60,
            },
            exceeds_blast_radius=score > blast_radius_cap,
            blast_radius_cap=blast_radius_cap,
            timestamp=datetime.utcnow(),
            methodology="single_action_v1",
        )

    async def update_impact(
        self, mission: Any, action_result: Any
    ) -> float:
        """
        Update cumulative impact after action execution.

        Args:
            mission: Mission being executed
            action_result: Result of executed action

        Returns:
            Updated cumulative impact score
        """
        # Estimate action impact
        action_impact = await self.estimate_action_impact(
            {
                "type": action_result.action_type,
                "target": {"asset": action_result.target},
            }
        )

        # Update cumulative with diminishing returns
        current_impact = mission.impact_score
        new_contribution = action_impact.score * 0.1  # Actions contribute incrementally

        updated_impact = min(current_impact + new_contribution, 100)

        # Check blast radius
        blast_radius_cap = self._get_blast_radius_cap(mission)
        if updated_impact > blast_radius_cap:
            raise BlastRadiusExceededError(
                f"Impact {updated_impact} exceeds blast radius cap {blast_radius_cap}",
                estimated_impact=updated_impact,
                blast_radius_cap=blast_radius_cap,
            )

        return updated_impact

    async def _calculate_factors(self, mission: Any) -> ImpactFactors:
        """Calculate impact factors for mission."""
        factors = ImpactFactors()

        scenario = mission.scenario

        # Target criticality
        targets = scenario.get("targets", [])
        if targets:
            criticalities = [
                self._criticality_map.get(t.get("type"), 0.5) for t in targets
            ]
            factors.target_criticality = max(criticalities)

        # Action severity
        phases = scenario.get("phases", [])
        severities = []
        for phase in phases:
            for action in phase.get("actions", []):
                severity = self._action_severity.get(action.get("type"), 0.5)
                severities.append(severity)

        if severities:
            factors.action_severity = max(severities)

        # Scope breadth
        factors.scope_breadth = min(len(targets) / 10, 1.0)

        # Persistence depth
        has_persistence = any(
            action.get("type") == "persistence"
            for phase in phases
            for action in phase.get("actions", [])
        )
        factors.persistence_depth = 1.0 if has_persistence else 0.0

        # Data sensitivity
        roe = mission.policy_envelope.get("roe", {})
        if roe.get("data_exfiltration_authorized"):
            factors.data_sensitivity = 0.8

        # Service disruption
        has_disruption = any(
            action.get("type") in ["service_disruption", "ransomware"]
            for phase in phases
            for action in phase.get("actions", [])
        )
        factors.service_disruption = 1.0 if has_disruption else 0.0

        return factors

    def _compute_score(self, factors: ImpactFactors) -> float:
        """Compute overall impact score from factors."""
        weights = {
            "target_criticality": 0.25,
            "action_severity": 0.25,
            "scope_breadth": 0.15,
            "persistence_depth": 0.10,
            "data_sensitivity": 0.15,
            "service_disruption": 0.10,
        }

        score = (
            factors.target_criticality * weights["target_criticality"]
            + factors.action_severity * weights["action_severity"]
            + factors.scope_breadth * weights["scope_breadth"]
            + factors.persistence_depth * weights["persistence_depth"]
            + factors.data_sensitivity * weights["data_sensitivity"]
            + factors.service_disruption * weights["service_disruption"]
        )

        return score * 100  # Scale to 0-100

    def _compute_confidence(self, factors: ImpactFactors) -> float:
        """Compute confidence in impact estimate."""
        # Higher confidence when factors are well-defined
        defined_factors = sum(
            1 for v in [
                factors.target_criticality,
                factors.action_severity,
                factors.scope_breadth,
            ]
            if v > 0
        )

        base_confidence = 0.5 + (defined_factors / 6) * 0.5

        return min(base_confidence, 0.95)

    def _get_blast_radius_cap(self, mission: Any) -> float:
        """Get blast radius cap from mission policy."""
        roe = mission.policy_envelope.get("roe", {})
        return roe.get("blast_radius_cap", self.config.tie.default_blast_radius_cap)

    async def predict_impact_ml(
        self, mission: Any
    ) -> Optional[ImpactEstimate]:
        """
        Use ML model for impact prediction.

        Args:
            mission: Mission to predict impact for

        Returns:
            ML-based impact estimate or None if model unavailable
        """
        if not self._model_loaded or not self._predictor:
            return None

        try:
            # Extract features for ML prediction
            features = await self._extract_features(mission)

            # Get ML prediction
            score, confidence = self._predictor.predict(features)

            blast_radius_cap = self._get_blast_radius_cap(mission)

            return ImpactEstimate(
                score=score,
                confidence=confidence,
                breakdown={"ml_prediction": score},
                exceeds_blast_radius=score > blast_radius_cap,
                blast_radius_cap=blast_radius_cap,
                timestamp=datetime.utcnow(),
                methodology="ml_neural_network_v1",
            )

        except Exception as e:
            logger.warning(f"ML prediction failed: {e}, falling back to rule-based")
            return await self.estimate_impact(mission)

    async def _extract_features(self, mission: Any) -> np.ndarray:
        """
        Extract feature vector for ML model from mission.

        Args:
            mission: Mission to extract features from

        Returns:
            Feature vector as numpy array
        """
        scenario = mission.scenario
        policy_envelope = mission.policy_envelope
        roe = policy_envelope.get("roe", {})

        # Target features
        targets = scenario.get("targets", [])
        max_criticality = 0.0
        for target in targets:
            target_type = target.get("type", "unknown")
            criticality = self._criticality_map.get(target_type, 0.5)
            max_criticality = max(max_criticality, criticality)

        num_targets = len(targets)

        # Action features
        kill_chain = scenario.get("kill_chain", [])
        max_severity = 0.0
        for phase in kill_chain:
            severity = self._action_severity.get(phase, 0.3)
            max_severity = max(max_severity, severity)

        num_phases = len(kill_chain)

        # Context features
        blast_radius_cap = roe.get("blast_radius_cap", 100)
        lateral_movement = 1.0 if roe.get("lateral_movement_authorized") else 0.0
        persistence = 1.0 if roe.get("persistence_authorized") else 0.0
        exfiltration = 1.0 if roe.get("data_exfiltration_authorized") else 0.0

        # Risk tier
        risk_tier = policy_envelope.get("risk_tier", 1)

        # Classification level encoding
        classification_map = {"UNCLASS": 0, "CUI": 1, "SECRET": 2, "TOPSECRET": 3}
        classification = classification_map.get(mission.classification_level, 0)

        # Combine into feature vector
        features = np.array([
            max_criticality,
            max_severity,
            num_targets / 10.0,  # Normalize
            num_phases / 10.0,  # Normalize
            blast_radius_cap / 100.0,  # Normalize
            lateral_movement,
            persistence,
            exfiltration,
            risk_tier / 4.0,  # Normalize
            classification / 3.0,  # Normalize
        ])

        return features

    def get_model_info(self) -> Optional[ModelInfo]:
        """Get information about loaded ML model."""
        if self._predictor:
            return self._predictor.model_info
        return None
