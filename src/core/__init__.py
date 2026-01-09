"""
Frost Gate Spear Core Module

Central orchestration and coordination for the platform.
"""

from .engine import FrostGateSpear
from .config import Config
from .mission import Mission, MissionState
from .exceptions import (
    FrostGateError,
    PolicyViolationError,
    ROEViolationError,
    SafetyConstraintError,
    MLSViolationError,
)

__all__ = [
    "FrostGateSpear",
    "Config",
    "Mission",
    "MissionState",
    "FrostGateError",
    "PolicyViolationError",
    "ROEViolationError",
    "SafetyConstraintError",
    "MLSViolationError",
]
