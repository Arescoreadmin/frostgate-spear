# Frost Gate Spear

**Autonomous Red Team Simulation Platform for DoD/Government Environments**

Frost Gate Spear is a comprehensive adversary emulation and security assessment platform designed for defense and government environments. It provides autonomous red team simulation capabilities with multi-level security (MLS), federated learning, and comprehensive safety controls.

## Features

- **Multi-Level Security (MLS)**: Supports UNCLASS, CUI, SECRET, and TOPSECRET classification rings with Bell-LaPadula enforcement
- **Policy-Driven Operations**: Every mission requires a policy envelope defining scope, ROE, and constraints
- **Rules of Engagement (ROE) Engine**: Automatic enforcement of scope, tools, targets, and blast radius limits
- **Adversary Personas**: Signed persona packs that emulate specific threat actors (APT29, ransomware operators, etc.)
- **Target Impact Estimator (TIE)**: ML-powered impact prediction and blast radius enforcement
- **Blue Box Explainer**: Human-readable explanations of all attack decisions and actions
- **Forensic Completeness**: WORM logging, Merkle tree integrity, and mission replay capability
- **Federated Learning**: Ring-isolated FL with differential privacy for model improvement
- **Governance Gates**: Security, Safety, Forensic, Impact, Performance, and Ops gates for promotion

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     FROST GATE SPEAR PLATFORM                        │
├─────────────────────────────────────────────────────────────────────┤
│  Policy Interpreter │ ROE Engine │ Safety Constraints │ MLS Manager │
├─────────────────────────────────────────────────────────────────────┤
│      Planner       │   Executor  │       TIE         │  Blue Box   │
├─────────────────────────────────────────────────────────────────────┤
│    Forensics       │ FL Controller │  Governance     │   Personas  │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
frostgate-spear/
├── src/                          # Core Python source code
│   ├── core/                     # Engine, config, mission, exceptions
│   ├── roe_engine/              # Rules of Engagement enforcement
│   ├── policy_interpreter/      # Policy envelope validation
│   ├── planner/                 # Attack plan generation
│   ├── sim/                     # Simulation and execution engine
│   ├── tie/                     # Target Impact Estimator
│   ├── blue_box/                # Explainability engine
│   ├── forensics/               # Audit trail and replay
│   ├── mls/                     # Multi-Level Security manager
│   ├── fl/                      # Federated Learning controller
│   └── governance/              # Approval and gate management
├── policy/                       # OPA Rego policies
│   ├── roe_policy.rego          # ROE enforcement rules
│   ├── safety_constraints.rego  # Safety constraint rules
│   ├── mls_policy.rego          # MLS enforcement rules
│   └── policy_envelope.schema.json
├── mls_rings/                    # Classification ring configurations
│   ├── unclass.yaml
│   ├── cui.yaml
│   ├── secret.yaml
│   └── topsecret.yaml
├── adversary_personas/           # Adversary persona definitions
│   ├── schema.json
│   ├── apt29_cozy_bear.json
│   └── generic_ransomware.json
├── fl_rings/                     # Federated learning configurations
│   ├── unclass.yaml
│   └── cui.yaml
├── sbom/provenance/             # SBOM and attestation schemas
├── docs/                        # Documentation
├── tests/                       # Test suite
├── configs/                     # Configuration files
└── .github/workflows/           # CI/CD pipelines
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/internal/frostgate-spear.git
cd frostgate-spear

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"
```

### Basic Usage

```python
import asyncio
from src import FrostGateSpear, Config

async def main():
    # Initialize with default config
    config = Config()
    engine = FrostGateSpear(config)

    # Start the engine
    await engine.start()

    # Create a mission
    mission = await engine.create_mission(
        policy_envelope={
            "envelope_id": "...",
            "mode": "simulation",
            "risk_tier": 1,
            "mission_type": "red_team",
            "classification_level": "UNCLASS",
            "scope_id": "scope-001",
            "approvals": [...],
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_to": "2025-12-31T23:59:59Z",
            "roe": {
                "allowed_assets": ["web-server-01", "db-server-01"],
                "blast_radius_cap": 50,
            }
        },
        scenario={
            "name": "Web Application Assessment",
            "targets": [{"name": "web-server-01", "type": "web_server"}]
        }
    )

    # Start mission execution
    await engine.start_mission(mission.mission_id)

    # Get status
    status = await engine.get_mission_status(mission.mission_id)
    print(status)

    await engine.stop()

asyncio.run(main())
```

## Safety Architecture

### Non-Negotiables

1. **Policy Envelopes Required** - Every action needs authorization
2. **ROE Engine Mandatory** - Automatic enforcement
3. **MLS Isolation** - No cross-ring contamination
4. **SIM-First Validation** - 1000 runs, zero violations
5. **Blast Radius Caps** - TIE enforced limits
6. **Forensic Completeness ≥ 95%** - Required for promotion
7. **No Autonomous Scope Expansion** - Explicit approval required
8. **Signed Personas Only** - Cannot override ROE or safety

### Red Lines

- No action outside mission ROE
- No automated classification modification
- No persona override of safety constraints
- No cross-ring contamination
- No destructive ops without AO signature
- No unsigned binaries

## Governance Gates

| Gate | Key Criteria |
|------|--------------|
| **Security** | Red team review, gov security review, tool catalog validated |
| **Safety** | 1000 SIM runs, 0 violations, FP rate < 5% |
| **Forensic** | Completeness ≥ 95%, replay success ≥ 95% |
| **Impact** | TIE scoring within envelope |
| **Performance** | Costs < budget, latency SLOs green |
| **Ops** | SOC replay successful, AO sign-off |

## Classification Rings

| Ring | Level | FL Epsilon | AO Required |
|------|-------|------------|-------------|
| UNCLASS | 0 | 1.0 | No |
| CUI | 1 | 0.5 | Risk 3+ |
| SECRET | 2 | 0.1 | Yes |
| TOPSECRET | 3 | 0.01 | Yes |

## Development

### Compliance & test dependencies

Install the test extras (includes numpy) before running compliance suites:

```sh
pip install .[test]
```

Run compliance in strict mode so missing numpy fails fast:

```sh
FGS_STRICT_COMPLIANCE=1 pytest -q
```

For locked networks, set your package indexes explicitly:

```sh
PIP_INDEX_URL=https://your.index/simple \
PIP_EXTRA_INDEX_URL=https://your.extra.index/simple \
pip install .[test]
```

For offline installs, populate a local wheelhouse and use the Makefile target:

```sh
mkdir -p vendor/wheels
pip download -d vendor/wheels .[test]
make deps-test-offline
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_core.py
```

### Code Quality

```bash
# Format code
black src tests

# Lint code
ruff check src tests

# Type checking
mypy src
```

## Documentation

- [Blueprint v6 (DoD/Gov Class)](docs/Blueprint_Frost_Gate_Spear_v6_gov_dod.md)
- [Policy Envelope Schema](policy/policy_envelope.schema.json)
- [Adversary Persona Schema](adversary_personas/schema.json)

## Compliance

Frost Gate Spear supports mapping to:

- NIST 800-53 (High)
- NIST 800-171
- FedRAMP High
- ICD-503
- CNSSI-1253
- FIPS 140-3
- STIG

## License

Proprietary - All rights reserved.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [SLSA Framework](https://slsa.dev/)
- [Open Policy Agent](https://www.openpolicyagent.org/)
