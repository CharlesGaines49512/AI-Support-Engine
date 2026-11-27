import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_CREDENTIAL_CANARY"

CREDENTIAL_LABELS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "api-key",
    "api key",
    "apikey",
    "access_token",
    "access-token",
    "access token",
    "accesstoken",
    "refresh_token",
    "refresh-token",
    "refresh token",
    "refreshtoken",
    "client_secret",
    "client-secret",
    "client secret",
    "clientsecret",
    "secret_key",
    "secret-key",
    "secret key",
    "secretkey",
)


@pytest.mark.parametrize("label", CREDENTIAL_LABELS)
@pytest.mark.parametrize("separator", ["=", ": "])
def test_credential_assignment_redacted(
    label: str,
    separator: str,
) -> None:
    original = f"{label}{separator}{CANARY}"
    result = sanitize_text(original)

    assert CANARY not in result.text

    assert result.text == (f"{label}{separator}[REDACTED_SECRET]")

    assert result.redaction_count == 1


@pytest.mark.parametrize("label", CREDENTIAL_LABELS)
def test_credential_assignment_rejected_outbound(
    label: str,
) -> None:
    original = f"{label}={CANARY}"

    with pytest.raises(UnsafeOutboundEvidenceError):
        validate_outbound_text(original, 2000)


@pytest.mark.parametrize("label", CREDENTIAL_LABELS)
def test_redacted_assignment_accepted_outbound(
    label: str,
) -> None:
    validate_outbound_text(
        f"{label}=[REDACTED_SECRET]",
        2000,
    )


@pytest.mark.parametrize(
    "label",
    [
        "api key",
        "access token",
        "refresh token",
        "client secret",
        "secret key",
    ],
)
def test_source_metadata_redacts_credentials(
    label: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    value, count = sanitizer.sanitize_source_name(f"{label}={CANARY}")

    assert value is not None
    assert CANARY not in value
    assert value == f"{label}=[REDACTED_SECRET]"
    assert count == 1


@pytest.mark.parametrize(
    "label",
    [
        "API KEY",
        "Access Token",
        "REFRESH TOKEN",
        "Client Secret",
        "SECRET KEY",
    ],
)
def test_case_insensitive_credential_recognition(
    label: str,
) -> None:
    result = sanitize_text(f"{label}={CANARY}")

    assert result.text == (f"{label}=[REDACTED_SECRET]")

    assert result.redaction_count == 1


@pytest.mark.parametrize(
    "message",
    [
        "Password reset completed.",
        "API key rotation completed.",
        "Access token expired.",
        "Refresh token renewal failed.",
        "Client secret rotation scheduled.",
        "Secret key configuration changed.",
        "Authorization request failed.",
        "Invalid credentials.",
        "Database connection failed.",
        "HTTP 503 Service Unavailable.",
    ],
)
def test_diagnostic_text_preserved(
    message: str,
) -> None:
    result = sanitize_text(message)

    assert result.text == message
    assert result.redaction_count == 0

    validate_outbound_text(message, 2000)


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        (
            f"Authorization: Bearer {CANARY}",
            "Authorization: Bearer [REDACTED_TOKEN]",
        ),
        (
            f"Authorization: Basic {CANARY}",
            "Authorization: Basic [REDACTED_TOKEN]",
        ),
        (
            "API credential: sk-proj-1234567890abcdef",
            "API credential: [REDACTED_API_KEY]",
        ),
        (
            "Synthetic credential: ghp_" + "a" * 36,
            "Synthetic credential: [REDACTED_GITHUB_TOKEN]",
        ),
        (
            "Contact user@example.com",
            "Contact [REDACTED_EMAIL]",
        ),
        (
            "postgresql://user:synthetic-password@localhost/db",
            "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
        ),
    ],
)
def test_specialized_redaction_behavior_preserved(
    original: str,
    expected: str,
) -> None:
    result = sanitize_text(original)

    assert result.text == expected
    assert result.redaction_count == 1

    validate_outbound_text(result.text, 2000)


@pytest.mark.parametrize(
    "label",
    [
        "api key",
        "secret key",
        "secret_key",
        "secret-key",
        "secretkey",
    ],
)
@pytest.mark.parametrize(
    "separator",
    ["=", ": "],
)
def test_incomplete_credential_assignment_rejected(
    label: str,
    separator: str,
) -> None:
    from app.logs.security import validate_sensitive_field
    from app.parsers.exceptions import UnsafeLogContentError

    with pytest.raises(UnsafeLogContentError):
        validate_sensitive_field(f"{label}{separator}")


@pytest.mark.parametrize(
    "label",
    [
        "api key",
        "secret key",
        "secret_key",
        "secret-key",
        "secretkey",
    ],
)
def test_fragmented_credential_assignment_rejected(
    label: str,
) -> None:
    from app.logs.security import validate_sensitive_field
    from app.parsers.exceptions import UnsafeLogContentError

    with pytest.raises(UnsafeLogContentError) as error:
        validate_sensitive_field(f"{label}=\n{CANARY}")

    assert CANARY not in str(error.value)


@pytest.mark.parametrize(
    "label",
    [
        "api key",
        "secret key",
        "secret_key",
        "secret-key",
        "secretkey",
    ],
)
def test_standalone_credential_label_rejected(
    label: str,
) -> None:
    from app.logs.security import validate_sensitive_field
    from app.parsers.exceptions import UnsafeLogContentError

    with pytest.raises(UnsafeLogContentError):
        validate_sensitive_field(label)
