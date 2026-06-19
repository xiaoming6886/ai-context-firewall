"""AI API target URL definitions and matching.

This module maps AI tool names to their known API endpoint hostnames
and provides helpers to determine whether a given URL targets an AI API.
"""

from __future__ import annotations

from urllib.parse import urlparse


# Mapping of AI tool names to their API hostnames.
# Each tool may have multiple possible upstream endpoints.
AI_TARGETS: dict[str, list[str]] = {
    "cursor": [
        "api2.cursor.sh",
    ],
    "copilot": [
        "api.githubcopilot.com",
        "copilot-proxy.githubusercontent.com",
    ],
    "claude": [
        "api.anthropic.com",
    ],
    "openai": [
        "api.openai.com",
    ],
}

# Flattened set of all target hostnames for fast O(1) lookup
_ALL_HOSTS: set[str] = {
    host
    for hosts in AI_TARGETS.values()
    for host in hosts
}


def is_ai_endpoint(url: str) -> bool:
    """Check whether *url* targets a known AI API endpoint.

    The check compares the lowercased hostname extracted from *url*
    against the known target hostnames in :data:`AI_TARGETS`.  Exact
    hostname match is used (subdomain hijacking is not missed).

    Args:
        url: The full URL to inspect, e.g. ``"https://api.openai.com/v1/…"``.

    Returns:
        ``True`` when the hostname belongs to a known AI API.
    """
    hostname = _extract_hostname(url)
    if hostname is None:
        return False
    return hostname in _ALL_HOSTS


def get_tool_name(url: str) -> str | None:
    """Return the AI-tool name that *url* belongs to.

    Args:
        url: The full URL to inspect.

    Returns:
        The tool key (e.g. ``"openai"``) or ``None`` when the URL does
        not match any known AI API.
    """
    hostname = _extract_hostname(url)
    if hostname is None:
        return None
    for tool, hosts in AI_TARGETS.items():
        if hostname in hosts:
            return tool
    return None


# ── internal helpers ──────────────────────────────────────────────────


def _extract_hostname(url: str) -> str | None:
    """Return the lowercased hostname from *url*, or ``None`` on failure."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    hostname = parsed.hostname
    if hostname is None:
        return None
    return hostname.lower()
