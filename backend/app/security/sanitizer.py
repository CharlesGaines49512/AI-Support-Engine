import re
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    """Represent sanitized text and redaction metadata."""

    text: str
    redaction_count: int

    @property
    def was_modified(self) -> bool:
        return self.redaction_count > 0


REDACTION_RULES: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
            r".*?"
            r"-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(
            r"\b([a-z][a-z0-9+.-]*://)"
            r"[^/\s:@]+:[^/\s@]+@",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_CREDENTIALS]@",
    ),
    (
        re.compile(
            r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+",
            re.IGNORECASE,
        ),
        r"\1 [REDACTED_TOKEN]",
    ),
    (
        re.compile(
            r"""(["']?\b(?:password|passwd|pwd|"""
            r"""api[_-]?key|access[_-]?token|"""
            r"""refresh[_-]?token|client[_-]?secret|"""
            r"""secret[_-]?key|token|secret)\b"""
            r"""["']?\s*[:=]\s*)"""
            r"""(?:"(?:\\[^\r\n]|[^"\\\r\n])*" """
            r"""|'(?:\\[^\r\n]|[^'\\\r\n])*'"""
            r"""|"[^\r\n]*|'[^\r\n]*"""
            r"""|[^\s,;&}\]]+)""",
            re.IGNORECASE | re.VERBOSE,
        ),
        r"\1[REDACTED_SECRET]",
    ),
    (
        re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
        "[REDACTED_API_KEY]",
    ),
    (
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}"
            r"|github_pat_[A-Za-z0-9_]{20,})\b"
        ),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    (
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "[REDACTED_SLACK_TOKEN]",
    ),
    (
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "[REDACTED_AWS_ACCESS_KEY]",
    ),
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_-]+"
            r"\.[A-Za-z0-9_-]+"
            r"\.[A-Za-z0-9_-]+\b"
        ),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(
            r"\b[A-Za-z0-9._%+-]+"
            r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        "[REDACTED_EMAIL]",
    ),
)


def sanitize_text(value: str) -> SanitizationResult:
    """Remove recognized sensitive values from untrusted text."""
    sanitized = value
    redaction_count = 0

    for pattern, replacement in REDACTION_RULES:
        sanitized, count = pattern.subn(
            replacement,
            sanitized,
        )

        redaction_count += count

    return SanitizationResult(
        text=sanitized,
        redaction_count=redaction_count,
    )
