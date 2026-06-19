"""Shared test fixtures and configuration."""

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to the tests/fixtures directory."""
    return Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def sample_data_dir(fixtures_dir: Path) -> Path:
    """Return the path to sample data within fixtures."""
    return fixtures_dir / "data"


# --- Fixture file paths for AI Context Firewall ---

@pytest.fixture
def sample_env_file(fixtures_dir: Path) -> Path:
    """Path to sample_env fixture file (.env format with fake secrets)."""
    return fixtures_dir / "sample_env"


@pytest.fixture
def aws_credentials_file(fixtures_dir: Path) -> Path:
    """Path to aws_credentials fixture file (AWS CLI credentials format)."""
    return fixtures_dir / "aws_credentials"


@pytest.fixture
def jwt_token_file(fixtures_dir: Path) -> Path:
    """Path to jwt_token fixture file (example JWT string)."""
    return fixtures_dir / "jwt_token"


@pytest.fixture
def github_pat_file(fixtures_dir: Path) -> Path:
    """Path to github_pat fixture file (GitHub Personal Access Tokens)."""
    return fixtures_dir / "github_pat"


@pytest.fixture
def mixed_safe_code_file(fixtures_dir: Path) -> Path:
    """Path to mixed_safe_code.py fixture file (safe Python code)."""
    return fixtures_dir / "mixed_safe_code.py"


@pytest.fixture
def mixed_secrets_file(fixtures_dir: Path) -> Path:
    """Path to mixed_secrets.json fixture file (JSON with secret fields)."""
    return fixtures_dir / "mixed_secrets.json"


@pytest.fixture
def large_binary_file(fixtures_dir: Path) -> Path:
    """Path to large_binary.dat fixture file (binary blob)."""
    return fixtures_dir / "large_binary.dat"


@pytest.fixture(scope="session", autouse=True)
def _ensure_binary_fixture(fixtures_dir: Path) -> None:
    """Ensure large_binary.dat contains exactly 20 bytes of real binary data."""
    path = fixtures_dir / "large_binary.dat"
    if not path.exists() or path.stat().st_size != 20:
        path.write_bytes(bytes(range(20)))
