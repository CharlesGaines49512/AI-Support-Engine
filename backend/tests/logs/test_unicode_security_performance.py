import subprocess
import sys
from pathlib import Path

import pytest

WORKER = r"""
import sys
import time

from app.security.sanitizer import sanitize_text
from app.logs.security import validate_sensitive_field
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.parsers.exceptions import UnsafeLogContentError

operation = sys.argv[1]
case = sys.argv[2]
size = int(sys.argv[3])


def repeat_complete(value, limit):
    return value * (limit // len(value))


builders = {
    "ascii_text": lambda n: "A" * n,
    "horizontal_spaces": lambda n: " " * n,
    "unicode_spaces": lambda n: "\u2003" * n,
    "compound_separators": lambda n: (
        "api" + ("_- " * n)[:n] + "key"
    ),
    "credential_near_match": lambda n: (
        "password" + " " * n + "validation completed"
    ),
    "fullwidth_label": lambda n: (
        "\uff41\uff50\uff49"
        + "\u3000" * n
        + "\uff4b\uff45\uff59"
    ),
    "authorization_near_match": lambda n: (
        "Bearer" + " " * n + "!"
    ),
    "incomplete_assignment": lambda n: (
        "password=" + "\u2003" * n
    ),
    "repetitive_labels": lambda n: repeat_complete(
        "password validation completed; ", n
    ),
    "repetitive_joiners": lambda n: (
        "api" + "\u200c" * n + "diagnostic"
    ),
    "international_text": lambda n: repeat_complete(
        "\u63a5\u7d9a\u5931\u6557 ", n
    ),
    "redacted_assignments": lambda n: repeat_complete(
        "password=[REDACTED_SECRET]; ", n
    ),
    "raw_assignments": lambda n: repeat_complete(
        "password=SYNTHETIC_PERFORMANCE_CANARY; ", n
    ),
}

value = builders[case](size)

started = time.perf_counter()

outcome = "accepted"

try:
    if operation == "sanitize":
        result = sanitize_text(value)

        if case == "raw_assignments":
            assert "SYNTHETIC_PERFORMANCE_CANARY" not in result.text
            assert result.was_modified
            outcome = "redacted"
        else:
            assert result.text == value
            assert not result.was_modified

    elif operation == "field":
        validate_sensitive_field(value)

    elif operation == "outbound":
        validate_outbound_text(value, len(value) + 1)

    else:
        raise AssertionError("Unknown security operation")

except (UnsafeLogContentError, UnsafeOutboundEvidenceError):
    outcome = "rejected"

elapsed = time.perf_counter() - started

print(f"{elapsed:.6f}|{outcome}")
"""

BACKEND_ROOT = Path(__file__).resolve().parents[2]

PROCESS_TIMEOUT_SECONDS = 15
PROCESSING_BUDGET_SECONDS = 2.0

CASES = (
    ("ascii_text", "accepted", "accepted", "accepted"),
    ("horizontal_spaces", "accepted", "accepted", "accepted"),
    ("unicode_spaces", "accepted", "accepted", "accepted"),
    ("compound_separators", "accepted", "rejected", "rejected"),
    ("credential_near_match", "accepted", "accepted", "accepted"),
    ("fullwidth_label", "accepted", "rejected", "rejected"),
    ("authorization_near_match", "accepted", "accepted", "accepted"),
    ("incomplete_assignment", "accepted", "rejected", "rejected"),
    ("repetitive_labels", "accepted", "accepted", "accepted"),
    ("repetitive_joiners", "accepted", "accepted", "accepted"),
    ("international_text", "accepted", "accepted", "accepted"),
    ("redacted_assignments", "accepted", "accepted", "accepted"),
    ("raw_assignments", "redacted", "accepted", "rejected"),
)

PARAMETERS = tuple(
    pytest.param(
        operation,
        case,
        expected,
        id=f"{operation}-{case}",
    )
    for case, sanitize, field, outbound in CASES
    for operation, expected in (
        ("sanitize", sanitize),
        ("field", field),
        ("outbound", outbound),
    )
)


@pytest.mark.parametrize(
    ("operation", "case", "expected"),
    PARAMETERS,
)
def test_unicode_security_performance(
    operation: str,
    case: str,
    expected: str,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            WORKER,
            operation,
            case,
            "20000",
        ],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        timeout=PROCESS_TIMEOUT_SECONDS,
        check=False,
    )

    assert result.returncode == 0, result.stderr

    elapsed_text, outcome = result.stdout.strip().split("|")

    elapsed = float(elapsed_text)

    assert outcome == expected

    assert 0 <= elapsed < PROCESSING_BUDGET_SECONDS, (
        f"{operation}/{case} exceeded the processing budget: {elapsed:.6f} seconds"
    )
