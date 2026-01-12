"""
Frost Gate Spear - Policy Module

OPA policy bundle management and verification.
Implements Gate M: OPA Bundle Signing.
"""

from .bundle_verify import (
    PolicyBundleVerificationError,
    PolicyBundleVerifier,
    verify_opa_bundle,
)

__all__ = [
    "PolicyBundleVerificationError",
    "PolicyBundleVerifier",
    "verify_opa_bundle",
]
