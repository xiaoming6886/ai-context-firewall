"""Unit tests for acf.proxy.targets."""

from typing import Optional

import pytest

from acf.proxy.targets import AI_TARGETS, is_ai_endpoint, get_tool_name


class TestAITargets:
    """Tests for AI API target URL detection."""

    # ── Structural integrity ───────────────────────────────────────────

    def test_ai_targets_has_all_four_tools(self) -> None:
        """AI_TARGETS must define entries for all expected AI tools."""
        assert set(AI_TARGETS.keys()) == {"cursor", "copilot", "claude", "openai"}

    def test_all_target_hostnames_are_valid(self) -> None:
        """Every hostname in AI_TARGETS must be a non-empty plausible host."""
        for tool, hosts in AI_TARGETS.items():
            assert len(hosts) >= 1, f"{tool!r} has no hostnames"
            for host in hosts:
                assert isinstance(host, str) and len(host) > 0
                assert "." in host, f"Invalid hostname {host!r}"
                assert "://" not in host, f"Hostname includes scheme: {host!r}"

    def test_copilot_has_two_endpoints(self) -> None:
        """GitHub Copilot uses both the primary and proxy endpoint."""
        assert len(AI_TARGETS["copilot"]) == 2

    # ── Positive match: api.openai.com ────────────────────────────────

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.openai.com/v1/chat/completions",
            "https://api.openai.com/v1/models",
            "https://api.openai.com/v1/embeddings",
        ],
    )
    def test_openai_endpoint_matches(self, url: str) -> None:
        assert is_ai_endpoint(url) is True
        assert get_tool_name(url) == "openai"

    # ── Positive match: api.anthropic.com ─────────────────────────────

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.anthropic.com/v1/messages",
            "https://api.anthropic.com/v1/complete",
        ],
    )
    def test_anthropic_endpoint_matches(self, url: str) -> None:
        assert is_ai_endpoint(url) is True
        assert get_tool_name(url) == "claude"

    # ── Positive match: api.githubcopilot.com ─────────────────────────

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.githubcopilot.com/chat/completions",
            "https://copilot-proxy.githubusercontent.com/v1/chat",
        ],
    )
    def test_copilot_endpoint_matches(self, url: str) -> None:
        assert is_ai_endpoint(url) is True
        assert get_tool_name(url) == "copilot"

    # ── Positive match: api2.cursor.sh ────────────────────────────────

    def test_cursor_endpoint_matches(self) -> None:
        url = "https://api2.cursor.sh/rest/chat"
        assert is_ai_endpoint(url) is True
        assert get_tool_name(url) == "cursor"

    # ── Negative match: google.com ────────────────────────────────────

    def test_google_does_not_match(self) -> None:
        """Non-AI endpoints must be rejected."""
        assert is_ai_endpoint("https://google.com/search") is False
        assert get_tool_name("https://google.com/search") is None

    # ── Subdomain match (must NOT match) ─────────────────────────────

    def test_subdomain_of_target_does_not_match(self) -> None:
        """A subdomain like evil-api.openai.com must NOT match openai.

        Only the exact hostname listed in AI_TARGETS should match.
        """
        url = "https://evil-api.openai.com/chat"
        assert is_ai_endpoint(url) is False
        assert get_tool_name(url) is None

    # ── Additional negative edge cases ────────────────────────────────

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com",
            "https://api.github.com/repos",
            "https://not-openai.com/api",
            "https://localhost:8080/health",
            "not-a-url",
            "",
        ],
    )
    def test_various_non_ai_urls_do_not_match(self, url: str) -> None:
        assert is_ai_endpoint(url) is False
        assert get_tool_name(url) is None

    # ── Case insensitivity ────────────────────────────────────────────

    @pytest.mark.parametrize(
        "url",
        [
            "HTTPS://API.OPENAI.COM/V1/CHAT",
            "https://API.OPENAI.COM/v1/chat",
        ],
    )
    def test_case_insensitive_hostname_matching(self, url: str) -> None:
        """Hostname matching must be case-insensitive."""
        assert is_ai_endpoint(url) is True
        assert get_tool_name(url) == "openai"

    # ── Port in URL ───────────────────────────────────────────────────

    def test_url_with_port_matches(self) -> None:
        """Standard port in URL should not affect hostname extraction."""
        assert is_ai_endpoint("https://api.openai.com:443/v1/chat") is True
        assert get_tool_name("https://api.openai.com:443/v1/chat") == "openai"
