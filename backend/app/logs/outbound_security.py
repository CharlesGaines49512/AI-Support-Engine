import re

from app.core.config import Settings
from app.logs.detection_rules import DETECTION_RULES
from app.logs.extraction_contracts import EvidenceEvent
from app.logs.security import (
    PRIVATE_KEY_BOUNDARY,
    validate_sensitive_field,
)
from app.models.log_enums import LogSeverity
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    UnsafeLogContentError,
)
from app.security.sanitizer import sanitize_text


class UnsafeOutboundEvidenceError(ValueError):
    """Evidence failed outbound security validation."""


RULE_CATEGORIES = {rule.rule_id: rule.category.value for rule in DETECTION_RULES}

RULE_CATEGORIES["SEV-001"] = "general"


SAFE_REDACTED_ASSIGNMENT = re.compile(
    (
        "[\"']?\\b(?:[p\\uff50][a\\uff41]"
        "[s\\uff53][s\\uff53][w\\uff57]["
        "o\\uff4f][r\\uff52][d\\uff44]|["
        "p\\uff50][a\\uff41][s\\uff53][s"
        "\\uff53][w\\uff57][d\\uff44]|[p"
        "\\uff50][w\\uff57][d\\uff44]|[a"
        "\\uff41][p\\uff50][i\\uff49][_ "
        "\\-\\u00a0\\u1680\\u2000-\\u200a\\"
        "u202f\\u205f\\u3000\\uff3f\\uff0"
        "d]*[k\\uff4b][e\\uff45][y\\uff5"
        "9]|[a\\uff41][c\\uff43][c\\uff4"
        "3][e\\uff45][s\\uff53][s\\uff53"
        "][_ \\-\\u00a0\\u1680\\u2000-\\u2"
        "00a\\u202f\\u205f\\u3000\\uff3f\\"
        "uff0d]*[t\\uff54][o\\uff4f][k\\"
        "uff4b][e\\uff45][n\\uff4e]|[r\\"
        "uff52][e\\uff45][f\\uff46][r\\u"
        "ff52][e\\uff45][s\\uff53][h\\uf"
        "f48][_ \\-\\u00a0\\u1680\\u2000-"
        "\\u200a\\u202f\\u205f\\u3000\\uff"
        "3f\\uff0d]*[t\\uff54][o\\uff4f]"
        "[k\\uff4b][e\\uff45][n\\uff4e]|"
        "[c\\uff43][l\\uff4c][i\\uff49]["
        "e\\uff45][n\\uff4e][t\\uff54][_"
        " \\-\\u00a0\\u1680\\u2000-\\u200a"
        "\\u202f\\u205f\\u3000\\uff3f\\uff"
        "0d]*[s\\uff53][e\\uff45][c\\uff"
        "43][r\\uff52][e\\uff45][t\\uff5"
        "4]|[s\\uff53][e\\uff45][c\\uff4"
        "3][r\\uff52][e\\uff45][t\\uff54"
        "][_ \\-\\u00a0\\u1680\\u2000-\\u2"
        "00a\\u202f\\u205f\\u3000\\uff3f\\"
        "uff0d]*[k\\uff4b][e\\uff45][y\\"
        "uff59]|[t\\uff54][o\\uff4f][k\\"
        "uff4b][e\\uff45][n\\uff4e]|[s\\"
        "uff53][e\\uff45][c\\uff43][r\\u"
        'ff52][e\\uff45][t\\uff54])\\b["'
        "']?\\s*[:=\\uff1a\\uff1d\\ufe55\\"
        "ufe66]\\s*\\[REDACTED_SECRET\\]"
        "(?=$|[\\s,;}&]|\\]+(?=$|[\\s,;}"
        "&]))"
    ),
    re.IGNORECASE,
)

SAFE_REDACTED_AUTHORIZATION = re.compile(
    (
        "\\b(?:[b\\uff42][e\\uff45][a\\uf"
        "f41][r\\uff52][e\\uff45][r\\uff"
        "52]|[b\\uff42][a\\uff41][s\\uff"
        "53][i\\uff49][c\\uff43])\\s+\\[R"
        "EDACTED_TOKEN\\](?=$|[\\s,;}&]"
        "|\\]+(?=$|[\\s,;}&]))"
    ),
    re.IGNORECASE,
)

SAFE_REDACTED_URI = re.compile(
    r"\b[a-z][a-z0-9+.-]*://\[REDACTED_CREDENTIALS\]@",
    re.IGNORECASE,
)


def validate_outbound_text(
    value: str,
    limit: int,
) -> None:
    """Reject unsafe text without modifying historical evidence."""

    if not isinstance(value, str):
        raise UnsafeOutboundEvidenceError("Invalid outbound evidence text.")

    if len(value) > limit:
        raise UnsafeOutboundEvidenceError(
            "Outbound evidence field exceeds its size limit."
        )

    try:
        validate_sensitive_field(value)
    except (
        InvalidLogEncodingError,
        UnsafeLogContentError,
    ):
        raise UnsafeOutboundEvidenceError(
            "Outbound evidence contains unsafe content."
        ) from None

    if PRIVATE_KEY_BOUNDARY.search(value) is not None:
        raise UnsafeOutboundEvidenceError(
            "Outbound evidence contains private key material."
        )

    inspection_value = value

    for pattern in (
        SAFE_REDACTED_ASSIGNMENT,
        SAFE_REDACTED_AUTHORIZATION,
        SAFE_REDACTED_URI,
    ):
        inspection_value = pattern.sub(
            " SANITIZED_PLACEHOLDER ",
            inspection_value,
        )

    if re.search(
        (
            "\\b(?:[b\\uff42][e\\uff45][a\\uf"
            "f41][r\\uff52][e\\uff45][r\\uff"
            "52]|[b\\uff42][a\\uff41][s\\uff"
            "53][i\\uff49][c\\uff43])\\s+\\["
        ),
        inspection_value,
        re.IGNORECASE,
    ):
        raise UnsafeOutboundEvidenceError(
            "Outbound evidence contains an invalid authorization marker."
        )

    try:
        validate_sensitive_field(inspection_value)
    except (
        InvalidLogEncodingError,
        UnsafeLogContentError,
    ):
        raise UnsafeOutboundEvidenceError(
            "Outbound evidence contains unsafe content."
        ) from None

    if sanitize_text(inspection_value).was_modified:
        raise UnsafeOutboundEvidenceError(
            "Outbound evidence contains recognizable sensitive data."
        )


def validate_outbound_event(
    event: EvidenceEvent,
    settings: Settings,
) -> None:
    """Validate diagnostic metadata and optional evidence fields."""

    if not isinstance(event.severity, LogSeverity):
        raise UnsafeOutboundEvidenceError("Invalid outbound evidence severity.")

    if type(event.details_omitted) is not bool:
        raise UnsafeOutboundEvidenceError("Invalid evidence omission indicator.")

    if any(rule_id not in RULE_CATEGORIES for rule_id in event.rule_ids):
        raise UnsafeOutboundEvidenceError("Unknown diagnostic rule identifier.")

    if len(set(event.rule_ids)) != len(event.rule_ids):
        raise UnsafeOutboundEvidenceError("Duplicate diagnostic rule identifier.")

    expected_categories = {RULE_CATEGORIES[rule_id] for rule_id in event.rule_ids}

    if set(event.categories) != expected_categories or len(
        set(event.categories)
    ) != len(event.categories):
        raise UnsafeOutboundEvidenceError("Inconsistent diagnostic categories.")

    fields = (
        (event.message, settings.log_max_message_chars),
        (event.exception, settings.log_max_message_chars),
        (event.error_code, settings.log_max_metadata_chars),
        (event.service_name, settings.log_max_metadata_chars),
        (event.event_timestamp, settings.log_max_metadata_chars),
    )

    if event.details_omitted and any(value is not None for value, _ in fields):
        raise UnsafeOutboundEvidenceError(
            "Omitted evidence contains unexpected details."
        )

    for value, limit in fields:
        if value is not None:
            validate_outbound_text(value, limit)
