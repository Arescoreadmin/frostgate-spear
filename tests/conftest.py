"""
Frost Gate Spear - Test Configuration

Dynamic repo root discovery to support running tests from any location.
Resolves hardcoded path issues per v6.1 requirements.
"""

import os
import sys
import subprocess
from pathlib import Path
from typing import Optional

import pytest


def discover_repo_root() -> Path:
    """
    Discover the repository root using multiple strategies.

    Priority:
    1. FGS_REPO_ROOT environment variable
    2. Git rev-parse --show-toplevel
    3. Path traversal from conftest.py location

    Returns:
        Path to repository root

    Raises:
        RuntimeError: If repo root cannot be discovered
    """
    # Strategy 1: Environment variable override
    env_root = os.environ.get("FGS_REPO_ROOT") or os.environ.get("FROSTGATE_REPO_ROOT")
    if env_root:
        root = Path(env_root)
        if root.is_dir() and (root / "pyproject.toml").is_file():
            return root

    # Strategy 2: Git rev-parse
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).parent,
        )
        git_root = Path(result.stdout.strip())
        if git_root.is_dir() and (git_root / "pyproject.toml").is_file():
            return git_root
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Strategy 3: Path traversal from conftest.py
    current = Path(__file__).resolve().parent
    for _ in range(10):  # Max 10 levels up
        if (current / "pyproject.toml").is_file() or (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent

    raise RuntimeError(
        "Could not discover repo root. Set FGS_REPO_ROOT environment variable "
        "or ensure tests are run from within the repository."
    )


# Discover and configure repo root
REPO_ROOT = discover_repo_root()

# Compatibility shim for legacy hardcoded paths in tests
_legacy_root = Path("/home/user/frostgate-spear")
try:
    if not _legacy_root.exists():
        _legacy_root.parent.mkdir(parents=True, exist_ok=True)
        _legacy_root.symlink_to(REPO_ROOT)
except OSError:
    pass

# Add src to Python path for imports
src_path = str(REPO_ROOT / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Fixture providing the repository root path."""
    return REPO_ROOT


@pytest.fixture(scope="session")
def data_dir(repo_root: Path, tmp_path_factory) -> Path:
    """
    Fixture providing a data directory for tests.

    Uses a temporary directory to avoid polluting the repo.
    """
    return tmp_path_factory.mktemp("frostgate_data")


@pytest.fixture(scope="session")
def trust_store_path(repo_root: Path) -> Optional[Path]:
    """Fixture providing the trust store path if it exists."""
    trust_store = repo_root / "integrity" / "trust_store.json"
    if trust_store.is_file():
        return trust_store
    return None


@pytest.fixture(scope="session")
def policy_dir(repo_root: Path) -> Path:
    """Fixture providing the policy directory path."""
    return repo_root / "policy"


@pytest.fixture(scope="session")
def examples_dir(repo_root: Path) -> Path:
    """Fixture providing the examples directory path."""
    return repo_root / "examples"


@pytest.fixture
def temp_sqlite_db(tmp_path) -> Path:
    """Fixture providing a temporary SQLite database path."""
    return tmp_path / "test_nonces.db"


@pytest.fixture
def sample_ed25519_keypair():
    """Fixture providing a sample Ed25519 keypair for testing."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import base64

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize keys
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return {
        "private_key": private_key,
        "public_key": public_key,
        "private_bytes": private_bytes,
        "public_bytes": public_bytes,
        "public_b64": base64.b64encode(public_bytes).decode("ascii"),
    }


@pytest.fixture
def valid_execution_permit(sample_ed25519_keypair):
    """Fixture providing a valid execution permit for testing."""
    from datetime import datetime, timezone, timedelta
    from uuid import uuid4
    import base64
    import json

    now = datetime.now(timezone.utc)

    permit_data = {
        "permit_id": str(uuid4()),
        "campaign_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "mode": "SIM",
        "risk_tier": 1,
        "credential_mode": "UNAUTHENTICATED",
        "tool_allowlist": [
            {"tool_id": "nmap", "version": "7.94", "certification": "SIM_SAFE"},
        ],
        "target_allowlist": [
            {"target_id": "HOST-123456789", "target_type": "HOST", "max_actions_per_minute": 60},
        ],
        "entrypoint_allowlist": [
            {"entrypoint_id": "ep-001", "region": "us-east-1", "network_zone": "PUBLIC"},
        ],
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": f"test-nonce-{uuid4()}",
        "jti": str(uuid4()),
    }

    # Sign the permit
    payload = json.dumps(permit_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = sample_ed25519_keypair["private_key"].sign(payload)

    permit_data["sig"] = {
        "algorithm": "Ed25519",
        "value": base64.b64encode(signature).decode("ascii"),
        "key_id": "test-key-001",
    }

    return {
        "permit": permit_data,
        "keypair": sample_ed25519_keypair,
    }
