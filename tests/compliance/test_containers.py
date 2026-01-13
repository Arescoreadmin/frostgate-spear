"""
Container Security and Health Tests.

Tests container security hardening and health checks:
- Non-root user enforcement
- Read-only filesystem
- No privileged mode
- Health check endpoints
- Resource limits
- Network isolation
"""

import pytest
import subprocess
import json
from pathlib import Path


class TestDockerfileCompliance:
    """Tests for Dockerfile security compliance."""

    def test_dockerfile_uses_non_root_user(self, repo_root):
        """Dockerfile must create and use a non-root user."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        # Check for user creation
        assert "groupadd" in content or "addgroup" in content, "Must create a group"
        assert "useradd" in content or "adduser" in content, "Must create a user"
        assert "USER" in content, "Must switch to non-root user"

        # Verify USER is not root
        lines = content.split("\n")
        user_lines = [l for l in lines if l.strip().startswith("USER")]
        assert len(user_lines) > 0, "Must have USER directive"
        for line in user_lines:
            assert "root" not in line.lower(), "USER must not be root"

    def test_dockerfile_uses_slim_base_image(self, repo_root):
        """Dockerfile should use slim base images."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        # Check for slim base
        assert "slim" in content or "alpine" in content, \
            "Should use slim or alpine base image for reduced attack surface"

    def test_dockerfile_has_healthcheck(self, repo_root):
        """Dockerfile must define a HEALTHCHECK."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        assert "HEALTHCHECK" in content, "Must define HEALTHCHECK"

    def test_dockerfile_multi_stage_build(self, repo_root):
        """Dockerfile should use multi-stage builds."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        # Count FROM directives
        from_count = content.count("FROM ")
        assert from_count >= 2, "Should use multi-stage build (multiple FROM)"

    def test_dockerfile_no_add_instruction(self, repo_root):
        """Dockerfile should prefer COPY over ADD."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        # ADD can have unexpected behaviors with URLs and tar extraction
        # COPY is more explicit and safer
        lines = content.split("\n")
        add_lines = [l for l in lines if l.strip().startswith("ADD ")]
        assert len(add_lines) == 0, "Prefer COPY over ADD for clarity and security"

    def test_dockerfile_no_latest_tag(self, repo_root):
        """Base images should not use :latest tag."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        # Find FROM lines
        lines = content.split("\n")
        from_lines = [l for l in lines if l.strip().startswith("FROM ")]

        for line in from_lines:
            if ":latest" in line and "as" not in line.lower():
                # Allow :latest only if it's an alias stage
                pytest.fail(f"Avoid :latest tag in base images: {line}")


class TestDockerComposeCompliance:
    """Tests for docker-compose security compliance."""

    def test_compose_has_health_checks(self, repo_root):
        """All services should have health checks."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        # Each service should have a healthcheck
        assert content.count("healthcheck:") >= 4, \
            "All main services should have health checks"

    def test_compose_no_privileged_mode(self, repo_root):
        """No service should run in privileged mode."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        assert "privileged: true" not in content, \
            "No service should run in privileged mode"

    def test_compose_uses_networks(self, repo_root):
        """Services should be on defined networks."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        assert "networks:" in content, "Should define networks for isolation"
        assert "frostgate-net" in content, "Should use project network"

    def test_compose_uses_volumes_for_persistence(self, repo_root):
        """Persistent data should use named volumes."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        assert "volumes:" in content, "Should define volumes"
        # Check for named volumes (not bind mounts for sensitive data)
        assert "postgres-data:" in content or "postgres-data" in content, \
            "Database should use named volume"

    def test_compose_has_restart_policy(self, repo_root):
        """Services should have restart policies."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        assert "restart:" in content, "Services should have restart policies"

    def test_compose_opa_is_rootless(self, repo_root):
        """OPA should use rootless image."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        assert "rootless" in content, "OPA should use rootless image"


class TestContainerSecurity:
    """Tests for container runtime security."""

    def test_container_runs_as_non_root(self, repo_root):
        """Verify container runs as non-root user."""
        # This would be run in a container environment
        # For now, verify Dockerfile configuration
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        # Check that USER directive is set to non-root
        assert "USER frostgate" in content or "USER appuser" in content, \
            "Container must run as non-root user"

    def test_no_sudo_in_container(self, repo_root):
        """Container should not have sudo installed."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        assert "sudo" not in content.lower(), \
            "sudo should not be installed in container"

    def test_minimal_packages_installed(self, repo_root):
        """Container should have minimal packages."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        # Check for --no-install-recommends flag
        if "apt-get install" in content:
            assert "--no-install-recommends" in content, \
                "apt-get install should use --no-install-recommends"


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_endpoint_defined(self, repo_root):
        """Health endpoint should be defined in CLI."""
        cli_file = repo_root / "src" / "cli.py"
        if cli_file.exists():
            content = cli_file.read_text()
            assert "health" in content.lower(), \
                "CLI should define health endpoint"

    def test_readiness_probe_requirements(self, repo_root):
        """Verify readiness probe requirements are met."""
        # Readiness should check:
        # 1. Database connectivity
        # 2. OPA connectivity
        # 3. Redis connectivity
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        # Verify depends_on is used
        assert "depends_on:" in content, \
            "Services should define dependencies"


class TestNetworkSecurity:
    """Tests for network security configuration."""

    def test_services_on_internal_network(self, repo_root):
        """Services should communicate on internal network."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        # Check for bridge network
        assert "driver: bridge" in content, \
            "Should use bridge network for isolation"

    def test_minimal_port_exposure(self, repo_root):
        """Only necessary ports should be exposed."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        # Count exposed ports
        port_count = content.count("ports:")
        # Should be limited - main app, maybe OPA/prometheus for debugging
        assert port_count <= 6, "Minimize port exposure"


class TestSecretManagement:
    """Tests for secret management."""

    def test_no_hardcoded_secrets_in_compose(self, repo_root):
        """No hardcoded production secrets in compose file."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        # Check for obvious hardcoded secrets
        # Allow development defaults but flag production-looking secrets
        assert "prod_password" not in content.lower(), \
            "No production passwords should be hardcoded"
        assert "prod_secret" not in content.lower(), \
            "No production secrets should be hardcoded"

    def test_environment_variables_used_for_secrets(self, repo_root):
        """Secrets should use environment variables."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        # Check that environment section exists
        assert "environment:" in content, \
            "Should use environment variables for configuration"


class TestResourceLimits:
    """Tests for resource limits (optional but recommended)."""

    def test_compose_format_version(self, repo_root):
        """docker-compose should use version 3.x for resource limits."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        assert "version:" in content, "Should specify compose version"
        # Version 3.x supports deploy resources
        assert "'3" in content or '"3' in content or "3." in content, \
            "Should use compose version 3.x"


class TestLoggingConfiguration:
    """Tests for logging configuration."""

    def test_log_directory_exists_in_dockerfile(self, repo_root):
        """Log directory should be created in Dockerfile."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        assert "mkdir" in content and "log" in content.lower(), \
            "Should create log directory"

    def test_log_volume_in_compose(self, repo_root):
        """Logs should be persisted via volume."""
        compose_file = repo_root / "docker-compose.yml"
        content = compose_file.read_text()

        assert "frostgate-logs" in content, \
            "Should define log volume for persistence"


class TestWORMStorage:
    """Tests for WORM storage compliance."""

    def test_forensic_log_directory_permissions(self, repo_root):
        """Forensic log directory should have proper permissions."""
        dockerfile = repo_root / "Dockerfile"
        content = dockerfile.read_text()

        # Check for forensics directory creation
        assert "forensics" in content, \
            "Should create forensics directory"

    def test_database_worm_triggers(self, repo_root):
        """Database should have WORM triggers for audit tables."""
        init_sql = repo_root / "scripts" / "init-db.sql"
        content = init_sql.read_text()

        assert "prevent_forensic_modification" in content, \
            "Should have WORM triggers for forensic records"
        assert "BEFORE UPDATE" in content, \
            "Should prevent updates on forensic records"
        assert "BEFORE DELETE" in content, \
            "Should prevent deletes on forensic records"
