"""Unit tests for acf.proxy.file_filter."""

import pytest

from acf.models.types import MatchType
from acf.proxy.file_filter import FileFilter


class TestFileFilter:
    """Tests for the FileFilter pre-filter."""

    # ── Fixtures ─────────────────────────────────────────────────────

    @pytest.fixture
    def filt(self) -> FileFilter:
        return FileFilter()

    # ── 1–9. Extension blocking (one per blocked extension) ──────────

    def test_block_env_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/project/config/.env")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".env"

    def test_block_pem_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/home/user/key.pem")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".pem"

    def test_block_p12_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/certs/cert.p12")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".p12"

    def test_block_pfx_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/certs/cert.pfx")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".pfx"

    def test_block_key_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/home/user/id_rsa.key")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".key"

    def test_block_p8_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/certs/private.p8")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".p8"

    def test_block_jks_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/certs/truststore.jks")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".jks"

    def test_block_keystore_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/certs/trust.keystore")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".keystore"

    def test_block_secret_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/project/config/.secret")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".secret"

    # ── 10–13. Path blocking (one per blocked path) ──────────────────

    def test_block_ssh_path(self, filt: FileFilter) -> None:
        matches = filt.check("~/.ssh/config")
        assert len(matches) >= 1
        assert any(m.rule_type == MatchType.PATH for m in matches)

    def test_block_aws_path(self, filt: FileFilter) -> None:
        matches = filt.check("~/.aws/credentials")
        assert len(matches) >= 1
        assert any(m.rule_type == MatchType.PATH for m in matches)

    def test_block_gcloud_path(self, filt: FileFilter) -> None:
        matches = filt.check("~/.gcloud/application_default_credentials.json")
        assert len(matches) >= 1
        assert any(m.rule_type == MatchType.PATH for m in matches)

    def test_block_azure_path(self, filt: FileFilter) -> None:
        matches = filt.check("~/.azure/config")
        assert len(matches) >= 1
        assert any(m.rule_type == MatchType.PATH for m in matches)

    # ── 14. PEM inline content blocking (>100 chars) ─────────────────

    def test_block_pem_inline_over_100_chars(self, filt: FileFilter) -> None:
        """A PEM private-key block whose base-64 content exceeds 100 characters."""
        body = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA1K7Q0v3b8z5F0a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y\n"
            "z1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3g4h5i6j7k8l9m0n\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        matches = filt.check(body)
        assert len(matches) >= 1
        assert any(m.rule_type == MatchType.PEM_BLOCK for m in matches)

    # ── 15. Normal code passes through ──────────────────────────────

    def test_normal_code_passes(self, filt: FileFilter) -> None:
        matches = filt.check('def hello():\n    print("Hello, world!")\n')
        assert len(matches) == 0

    # ── 16. Case-insensitive extension matching ─────────────────────

    def test_case_insensitive_extension(self, filt: FileFilter) -> None:
        matches = filt.check("/project/config/.ENV")
        assert len(matches) == 1
        assert matches[0].rule_type == MatchType.EXTENSION
        assert matches[0].matched_value == ".env"

    # ── 17–18. should_block convenience API ─────────────────────────

    def test_should_block_returns_true_when_blocked(self, filt: FileFilter) -> None:
        blocked, matches = filt.should_block("/project/.env")
        assert blocked is True
        assert len(matches) == 1

    def test_should_block_returns_false_when_clean(self, filt: FileFilter) -> None:
        blocked, matches = filt.should_block("/project/main.py")
        assert blocked is False
        assert len(matches) == 0
