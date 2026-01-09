"""
Frost Gate Spear Configuration Management

Centralized configuration for all subsystems.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class Environment(Enum):
    """Deployment environments."""
    SIMULATION = "simulation"
    LAB = "lab"
    CANARY = "canary"
    PRODUCTION = "production"
    MISSION = "mission"


class ClassificationLevel(Enum):
    """Classification levels for MLS."""
    UNCLASS = "UNCLASS"
    CUI = "CUI"
    SECRET = "SECRET"
    TOPSECRET = "TOPSECRET"


@dataclass
class PolicyConfig:
    """Policy-related configuration."""
    roe_policy_path: str = "policy/roe_policy.rego"
    safety_policy_path: str = "policy/safety_constraints.rego"
    mls_policy_path: str = "policy/mls_policy.rego"
    envelope_schema_path: str = "policy/policy_envelope.schema.json"


@dataclass
class MLSConfig:
    """Multi-Level Security configuration."""
    rings_path: str = "mls_rings/"
    default_ring: ClassificationLevel = ClassificationLevel.UNCLASS
    cross_ring_enabled: bool = False
    ring_configs: Dict[str, str] = field(default_factory=lambda: {
        "UNCLASS": "mls_rings/unclass.yaml",
        "CUI": "mls_rings/cui.yaml",
        "SECRET": "mls_rings/secret.yaml",
        "TOPSECRET": "mls_rings/topsecret.yaml",
    })


@dataclass
class ForensicsConfig:
    """Forensics subsystem configuration."""
    completeness_threshold: float = 0.95
    replay_success_threshold: float = 0.95
    worm_storage_enabled: bool = True
    external_timestamp_enabled: bool = True
    merkle_tree_enabled: bool = True
    hash_algorithm: str = "SHA-256"
    log_retention_days: int = 730
    storage_path: str = "/var/log/frostgate/forensics"


@dataclass
class TIEConfig:
    """Target Impact Estimator configuration."""
    default_blast_radius_cap: float = 50.0
    impact_accuracy_threshold: float = 0.90
    model_path: str = "models/tie/"
    enable_ml_predictions: bool = True


@dataclass
class PlannerConfig:
    """Planner subsystem configuration."""
    max_plan_depth: int = 20
    max_concurrent_branches: int = 5
    enable_counterfactual: bool = True
    persona_bias_weight: float = 0.7


@dataclass
class FLConfig:
    """Federated Learning configuration."""
    enabled: bool = True
    rings_path: str = "fl_rings/"
    default_aggregation: str = "fedavg"
    differential_privacy_enabled: bool = True
    default_epsilon: float = 1.0
    default_delta: float = 1e-5
    min_participants: int = 3


@dataclass
class GovernanceConfig:
    """Governance configuration."""
    require_approvals: bool = True
    sim_runs_required: int = 1000
    policy_violations_allowed: int = 0
    enable_budget_enforcement: bool = True


@dataclass
class RPCConfig:
    """RPC/API configuration."""
    mtls_enabled: bool = True
    opa_check_enabled: bool = True
    per_service_identity: bool = True
    session_timeout_minutes: int = 30


@dataclass
class Config:
    """
    Main configuration class for Frost Gate Spear.

    Aggregates all subsystem configurations.
    """
    # Core settings
    environment: Environment = Environment.SIMULATION
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASS
    base_path: str = field(default_factory=lambda: os.getcwd())

    # Subsystem configs
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    mls: MLSConfig = field(default_factory=MLSConfig)
    forensics: ForensicsConfig = field(default_factory=ForensicsConfig)
    tie: TIEConfig = field(default_factory=TIEConfig)
    planner: PlannerConfig = field(default_factory=PlannerConfig)
    fl: FLConfig = field(default_factory=FLConfig)
    governance: GovernanceConfig = field(default_factory=GovernanceConfig)
    rpc: RPCConfig = field(default_factory=RPCConfig)

    # Operational settings
    log_level: str = "INFO"
    metrics_enabled: bool = True
    tracing_enabled: bool = True

    @classmethod
    def from_file(cls, config_path: str) -> "Config":
        """
        Load configuration from a YAML file.

        Args:
            config_path: Path to configuration YAML file

        Returns:
            Populated Config object
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """
        Create configuration from dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            Populated Config object
        """
        config = cls()

        # Core settings
        if "environment" in data:
            config.environment = Environment(data["environment"])
        if "classification_level" in data:
            config.classification_level = ClassificationLevel(
                data["classification_level"]
            )
        if "base_path" in data:
            config.base_path = data["base_path"]

        # Subsystem configs
        if "policy" in data:
            config.policy = PolicyConfig(**data["policy"])
        if "mls" in data:
            mls_data = data["mls"].copy()
            if "default_ring" in mls_data:
                mls_data["default_ring"] = ClassificationLevel(mls_data["default_ring"])
            config.mls = MLSConfig(**mls_data)
        if "forensics" in data:
            config.forensics = ForensicsConfig(**data["forensics"])
        if "tie" in data:
            config.tie = TIEConfig(**data["tie"])
        if "planner" in data:
            config.planner = PlannerConfig(**data["planner"])
        if "fl" in data:
            config.fl = FLConfig(**data["fl"])
        if "governance" in data:
            config.governance = GovernanceConfig(**data["governance"])
        if "rpc" in data:
            config.rpc = RPCConfig(**data["rpc"])

        # Operational settings
        if "log_level" in data:
            config.log_level = data["log_level"]
        if "metrics_enabled" in data:
            config.metrics_enabled = data["metrics_enabled"]
        if "tracing_enabled" in data:
            config.tracing_enabled = data["tracing_enabled"]

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "environment": self.environment.value,
            "classification_level": self.classification_level.value,
            "base_path": self.base_path,
            "policy": {
                "roe_policy_path": self.policy.roe_policy_path,
                "safety_policy_path": self.policy.safety_policy_path,
                "mls_policy_path": self.policy.mls_policy_path,
                "envelope_schema_path": self.policy.envelope_schema_path,
            },
            "mls": {
                "rings_path": self.mls.rings_path,
                "default_ring": self.mls.default_ring.value,
                "cross_ring_enabled": self.mls.cross_ring_enabled,
                "ring_configs": self.mls.ring_configs,
            },
            "forensics": {
                "completeness_threshold": self.forensics.completeness_threshold,
                "replay_success_threshold": self.forensics.replay_success_threshold,
                "worm_storage_enabled": self.forensics.worm_storage_enabled,
                "external_timestamp_enabled": self.forensics.external_timestamp_enabled,
                "merkle_tree_enabled": self.forensics.merkle_tree_enabled,
                "hash_algorithm": self.forensics.hash_algorithm,
                "log_retention_days": self.forensics.log_retention_days,
                "storage_path": self.forensics.storage_path,
            },
            "tie": {
                "default_blast_radius_cap": self.tie.default_blast_radius_cap,
                "impact_accuracy_threshold": self.tie.impact_accuracy_threshold,
                "model_path": self.tie.model_path,
                "enable_ml_predictions": self.tie.enable_ml_predictions,
            },
            "planner": {
                "max_plan_depth": self.planner.max_plan_depth,
                "max_concurrent_branches": self.planner.max_concurrent_branches,
                "enable_counterfactual": self.planner.enable_counterfactual,
                "persona_bias_weight": self.planner.persona_bias_weight,
            },
            "fl": {
                "enabled": self.fl.enabled,
                "rings_path": self.fl.rings_path,
                "default_aggregation": self.fl.default_aggregation,
                "differential_privacy_enabled": self.fl.differential_privacy_enabled,
                "default_epsilon": self.fl.default_epsilon,
                "default_delta": self.fl.default_delta,
                "min_participants": self.fl.min_participants,
            },
            "governance": {
                "require_approvals": self.governance.require_approvals,
                "sim_runs_required": self.governance.sim_runs_required,
                "policy_violations_allowed": self.governance.policy_violations_allowed,
                "enable_budget_enforcement": self.governance.enable_budget_enforcement,
            },
            "rpc": {
                "mtls_enabled": self.rpc.mtls_enabled,
                "opa_check_enabled": self.rpc.opa_check_enabled,
                "per_service_identity": self.rpc.per_service_identity,
                "session_timeout_minutes": self.rpc.session_timeout_minutes,
            },
            "log_level": self.log_level,
            "metrics_enabled": self.metrics_enabled,
            "tracing_enabled": self.tracing_enabled,
        }

    def validate(self) -> List[str]:
        """
        Validate configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check paths exist
        base = Path(self.base_path)
        if not base.exists():
            errors.append(f"Base path does not exist: {self.base_path}")

        # Validate thresholds
        if not 0 <= self.forensics.completeness_threshold <= 1:
            errors.append("Forensic completeness threshold must be between 0 and 1")

        if not 0 <= self.forensics.replay_success_threshold <= 1:
            errors.append("Replay success threshold must be between 0 and 1")

        if self.tie.default_blast_radius_cap < 0:
            errors.append("Blast radius cap must be non-negative")

        if self.fl.default_epsilon <= 0:
            errors.append("FL epsilon must be positive")

        if self.fl.min_participants < 1:
            errors.append("FL min participants must be at least 1")

        return errors
