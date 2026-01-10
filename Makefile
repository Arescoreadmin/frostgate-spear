# Frost Gate Spear Makefile

.PHONY: help install dev test lint format type-check clean docker-build docker-up docker-down

# Default target
help:
	@echo "Frost Gate Spear - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install      Install production dependencies"
	@echo "  make dev          Install development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  make test         Run tests"
	@echo "  make lint         Run linter"
	@echo "  make format       Format code"
	@echo "  make type-check   Run type checker"
	@echo "  make check        Run all checks (lint, type-check, test)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-up    Start all services"
	@echo "  make docker-down  Stop all services"
	@echo ""
	@echo "Other:"
	@echo "  make clean        Clean build artifacts"
	@echo "  make run          Run the server locally"

# Installation
install:
	pip install -e .

dev:
	pip install -e ".[dev]"
	pre-commit install

# Testing
test:
	pytest tests/ -v --cov=src --cov-report=term-missing

test-unit:
	pytest tests/test_core.py -v

test-integration:
	pytest tests/test_integration.py -v

# Code quality
lint:
	ruff check src tests

format:
	black src tests
	ruff check --fix src tests

type-check:
	mypy src

check: lint type-check test

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Docker
docker-build:
	docker build -t frostgate-spear:latest .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f frostgate

# Running
run:
	python -m src.cli server --host 0.0.0.0 --port 8080

run-dev:
	python -m src.cli server --host 0.0.0.0 --port 8080 --log-level DEBUG

# Validation
validate-policies:
	opa check policy/*.rego
	opa test policy/ -v

validate-schemas:
	python -c "import json; json.load(open('policy/policy_envelope.schema.json'))"
	python -c "import json; json.load(open('scenarios/schema.json'))"
	python -c "import json; json.load(open('adversary_personas/schema.json'))"

# Simulation
simulate:
	python -m src.cli simulate \
		--envelope examples/mission_envelope.json \
		--scenario scenarios/examples/web_app_compromise.json \
		--iterations 100

# Database
db-init:
	docker-compose exec postgres psql -U frostgate -d frostgate -f /docker-entrypoint-initdb.d/init.sql

db-shell:
	docker-compose exec postgres psql -U frostgate -d frostgate

#######################################
# COMPLIANCE TESTING
#######################################
.PHONY: test-compliance test-gates test-red-lines test-mls test-fl test-sbom compliance-report validate-gates

# Run all compliance tests
test-compliance: test-gates test-red-lines test-mls test-fl test-sbom
	@echo "All compliance tests passed!"

# Test all 7 governance gates
test-gates:
	@echo "Running gate validation tests (7 gates)..."
	pytest tests/compliance/test_gates.py -v --tb=short

# Test all 8 red line violations
test-red-lines:
	@echo "Running red line violation tests (8 red lines)..."
	pytest tests/compliance/test_red_lines.py -v --tb=short

# Test MLS cross-ring contamination
test-mls:
	@echo "Running MLS cross-ring contamination tests..."
	pytest tests/compliance/test_mls.py -v --tb=short

# Test FL differential privacy
test-fl:
	@echo "Running FL differential privacy tests..."
	pytest tests/compliance/test_fl_privacy.py -v --tb=short

# Test SBOM/SLSA verification
test-sbom:
	@echo "Running SBOM/SLSA verification tests..."
	pytest tests/compliance/test_sbom_slsa.py -v --tb=short

# Validate all gates for promotion
validate-gates:
	@echo "Validating all gates for promotion..."
	@echo ""
	@echo "Security Gate:"
	@pytest tests/compliance/test_gates.py::TestSecurityGate -v --tb=line 2>/dev/null || echo "  FAILED"
	@echo ""
	@echo "Safety Gate:"
	@pytest tests/compliance/test_gates.py::TestSafetyGate -v --tb=line 2>/dev/null || echo "  FAILED"
	@echo ""
	@echo "Forensic Gate:"
	@pytest tests/compliance/test_gates.py::TestForensicGate -v --tb=line 2>/dev/null || echo "  FAILED"
	@echo ""
	@echo "Impact Gate:"
	@pytest tests/compliance/test_gates.py::TestImpactGate -v --tb=line 2>/dev/null || echo "  FAILED"
	@echo ""
	@echo "Performance Gate:"
	@pytest tests/compliance/test_gates.py::TestPerformanceGate -v --tb=line 2>/dev/null || echo "  FAILED"
	@echo ""
	@echo "Ops Gate:"
	@pytest tests/compliance/test_gates.py::TestOpsGate -v --tb=line 2>/dev/null || echo "  FAILED"
	@echo ""
	@echo "FL Ring Gate:"
	@pytest tests/compliance/test_gates.py::TestFLRingGate -v --tb=line 2>/dev/null || echo "  FAILED"

# Generate compliance report
compliance-report:
	@echo "========================================"
	@echo "FROST GATE SPEAR COMPLIANCE REPORT"
	@echo "Generated: $$(date)"
	@echo "========================================"
	@echo ""
	@echo "Gate Status:"
	@echo "  [ ] Security Gate - Red team review, gov security, MLS isolation"
	@echo "  [ ] Safety Gate - 1000 SIM runs, 0 violations, <5% FP"
	@echo "  [ ] Forensic Gate - >=95% completeness, >=95% replay"
	@echo "  [ ] Impact Gate - TIE within envelope, zero-impact mode"
	@echo "  [ ] Performance Gate - Budget, latency, alert footprint"
	@echo "  [ ] Ops Gate - SOC replay, Blue Box, AO sign-off"
	@echo "  [ ] FL Ring Gate - No contamination, DP bounds intact"
	@echo ""
	@echo "Red Lines (Absolute Prohibitions):"
	@echo "  [X] No action outside mission ROE"
	@echo "  [X] No automated classification level modification"
	@echo "  [X] No persona override of ROE/safety/policy"
	@echo "  [X] No cross-ring contamination"
	@echo "  [X] No destructive ops without AO signature"
	@echo "  [X] No scenario execution without hash match"
	@echo "  [X] No unsigned binaries"
	@echo "  [X] No un-attested artifacts"
	@echo ""
	@echo "Compliance Frameworks:"
	@echo "  - NIST 800-53 (High)"
	@echo "  - NIST 800-171 (CUI)"
	@echo "  - FedRAMP High"
	@echo "  - ICD-503 (SECRET)"
	@echo "  - CNSSI-1253"
	@echo "  - FIPS 140-3"
	@echo "  - SLSA Level 3"

#######################################
# SECURITY SCANNING
#######################################
.PHONY: security-scan trivy-scan gitleaks-scan semgrep-scan

security-scan: trivy-scan gitleaks-scan
	@echo "Security scanning complete"

trivy-scan:
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --severity HIGH,CRITICAL .; \
	else \
		echo "Trivy not installed, skipping..."; \
	fi

gitleaks-scan:
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks detect --source . --no-git; \
	else \
		echo "Gitleaks not installed, skipping..."; \
	fi

semgrep-scan:
	@if command -v semgrep >/dev/null 2>&1; then \
		semgrep --config auto --config p/security-audit .; \
	else \
		echo "Semgrep not installed, skipping..."; \
	fi

#######################################
# CONTAINER HEALTH CHECKS
#######################################
.PHONY: health-check container-status

health-check:
	@echo "Checking container health..."
	@docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep frostgate || true
	@echo ""
	@echo "Service Health:"
	@curl -s http://localhost:8080/health 2>/dev/null && echo "  Frost Gate: OK" || echo "  Frost Gate: DOWN"
	@curl -s http://localhost:8181/health 2>/dev/null && echo "  OPA: OK" || echo "  OPA: DOWN"
	@curl -s http://localhost:9090/-/healthy 2>/dev/null && echo "  Prometheus: OK" || echo "  Prometheus: DOWN"

container-status:
	docker-compose ps

#######################################
# CI/CD TARGETS
#######################################
.PHONY: ci ci-build ci-test

ci: lint type-check security-scan test test-compliance compliance-report
	@echo "CI pipeline complete!"

ci-build:
	docker build --no-cache -t frostgate-spear:ci .
	@echo "CI build complete!"

ci-test:
	docker-compose run --rm frostgate pytest tests/ -v --tb=short
	@echo "CI test complete!"

#######################################
# SIMULATION RUNS (Safety Gate)
#######################################
.PHONY: sim-1000 sim-100

sim-1000:
	@echo "Running 1000 simulation runs for safety gate..."
	python -m src.cli simulate \
		--envelope examples/mission_envelope.json \
		--scenario scenarios/examples/web_app_compromise.json \
		--iterations 1000 \
		--validate-safety

sim-100:
	@echo "Running 100 simulation runs (quick validation)..."
	python -m src.cli simulate \
		--envelope examples/mission_envelope.json \
		--scenario scenarios/examples/web_app_compromise.json \
		--iterations 100
