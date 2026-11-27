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
            (
                "\\b([b\\uff42][e\\uff45][a\\uff4"
                "1][r\\uff52][e\\uff45][r\\uff52"
                "]|[b\\uff42][a\\uff41][s\\uff53"
                "][i\\uff49][c\\uff43])\\s+[A-Za"
                "-z0-9._~+/=-]+"
            ),
            re.IGNORECASE,
        ),
        r"\1 [REDACTED_TOKEN]",
    ),
    (
        re.compile(
            (
                "([\"']?\\b(?:[p\\uff50][a\\uff41"
                "][s\\uff53][s\\uff53][w\\uff57]"
                "[o\\uff4f][r\\uff52][d\\uff44]|"
                "[p\\uff50][a\\uff41][s\\uff53]["
                "s\\uff53][w\\uff57][d\\uff44]|["
                "p\\uff50][w\\uff57][d\\uff44]|["
                "a\\uff41][p\\uff50][i\\uff49][_"
                " \\-\\u00a0\\u1680\\u2000-\\u200a"
                "\\u202f\\u205f\\u3000\\uff3f\\uff"
                "0d]*[k\\uff4b][e\\uff45][y\\uff"
                "59]|[a\\uff41][c\\uff43][c\\uff"
                "43][e\\uff45][s\\uff53][s\\uff5"
                "3][_ \\-\\u00a0\\u1680\\u2000-\\u"
                "200a\\u202f\\u205f\\u3000\\uff3f"
                "\\uff0d]*[t\\uff54][o\\uff4f][k"
                "\\uff4b][e\\uff45][n\\uff4e]|[r"
                "\\uff52][e\\uff45][f\\uff46][r\\"
                "uff52][e\\uff45][s\\uff53][h\\u"
                "ff48][_ \\-\\u00a0\\u1680\\u2000"
                "-\\u200a\\u202f\\u205f\\u3000\\uf"
                "f3f\\uff0d]*[t\\uff54][o\\uff4f"
                "][k\\uff4b][e\\uff45][n\\uff4e]"
                "|[c\\uff43][l\\uff4c][i\\uff49]"
                "[e\\uff45][n\\uff4e][t\\uff54]["
                "_ \\-\\u00a0\\u1680\\u2000-\\u200"
                "a\\u202f\\u205f\\u3000\\uff3f\\uf"
                "f0d]*[s\\uff53][e\\uff45][c\\uf"
                "f43][r\\uff52][e\\uff45][t\\uff"
                "54]|[s\\uff53][e\\uff45][c\\uff"
                "43][r\\uff52][e\\uff45][t\\uff5"
                "4][_ \\-\\u00a0\\u1680\\u2000-\\u"
                "200a\\u202f\\u205f\\u3000\\uff3f"
                "\\uff0d]*[k\\uff4b][e\\uff45][y"
                "\\uff59]|[t\\uff54][o\\uff4f][k"
                "\\uff4b][e\\uff45][n\\uff4e]|[s"
                "\\uff53][e\\uff45][c\\uff43][r\\"
                "uff52][e\\uff45][t\\uff54])\\b["
                "\"']?\\s*[:=\\uff1a\\uff1d\\ufe55"
                "\\ufe66]\\s*)(?!\\[REDACTED_SEC"
                "RET\\](?=$|[\\s,;}&]|\\]+(?=$|["
                "\\s,;}&])))(?:\\[REDACTED[^\\s,"
                ';&}]*|"(?:\\\\[^\\r\\n]|[^"\\\\\\r\\'
                "n])*\" |'(?:\\\\[^\\r\\n]|[^'\\\\\\r"
                "\\n])*'|\"[^\\r\\n]*|'[^\\r\\n]*|["
                "^\\s,;&}\\]]+)"
            ),
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
