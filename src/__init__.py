"""
Frost Gate Spear - Autonomous Red Team Simulation Platform

A DoD/Government-class adversary emulation and security assessment platform
with multi-level security, federated learning, and comprehensive safety controls.

Version: 1.0.0
Classification: Supports UNCLASS, CUI, SECRET, TOPSECRET rings
"""

__version__ = "1.0.0"
__author__ = "Frost Gate Spear Team"

from .core import FrostGateSpear
from .core.config import Config
from .core.exceptions import (
    FrostGateError,
    PolicyViolationError,
    ROEViolationError,
    SafetyConstraintError,
    MLSViolationError,
)

__all__ = [
    "FrostGateSpear",
    "Config",
    "FrostGateError",
    "PolicyViolationError",
    "ROEViolationError",
    "SafetyConstraintError",
    "MLSViolationError",
]
