import pytest

from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)

CANARY = "SYNTHETIC_RESIDUAL_CREDENTIAL_CANARY"


@pytest.mark.parametrize(
    "label",
    [
        "password",
        "api_key",
        "api key",
        "access_token",
        "client_secret",
        "secret key",
    ],
)
@pytest.mark.parametrize(
    "suffix",
    [
        CANARY,
        "-" + CANARY,
        "_" + CANARY,
    ],
)
def test_assignment_marker_suffix_rejected(
    label: str,
    suffix: str,
) -> None:
    value = f"{label}=[REDACTED_SECRET]{suffix}"

    with pytest.raises(UnsafeOutboundEvidenceError) as error:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(error.value)


@pytest.mark.parametrize(
    "scheme",
    ["Bearer", "Basic"],
)
@pytest.mark.parametrize(
    "suffix",
    [
        CANARY,
        "-" + CANARY,
        "_" + CANARY,
    ],
)
def test_authorization_marker_suffix_rejected(
    scheme: str,
    suffix: str,
) -> None:
    value = f"{scheme} [REDACTED_TOKEN]{suffix}"

    with pytest.raises(UnsafeOutboundEvidenceError) as error:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(error.value)


@pytest.mark.parametrize(
    "marker",
    [
        "[REDACTED_SECRET",
        "[REDACTED_SECRET_EXTRA]",
        "[REDACTED_SECRET=" + CANARY + "]",
        "[REDACTED_SECRETX]",
        "[REDACTED_TOKEN]",
        "[REDACTED_API_KEY]",
    ],
)
def test_invalid_assignment_marker_rejected(
    marker: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError):
        validate_outbound_text(
            f"password={marker}",
            2000,
        )


@pytest.mark.parametrize(
    "marker",
    [
        "[REDACTED_TOKEN",
        "[REDACTED_TOKEN_EXTRA]",
        "[REDACTED_TOKEN=" + CANARY + "]",
        "[REDACTED_TOKENX]",
        "[REDACTED_SECRET]",
        "[REDACTED_API_KEY]",
    ],
)
def test_invalid_authorization_marker_rejected(
    marker: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError):
        validate_outbound_text(
            f"Authorization: Bearer {marker}",
            2000,
        )


@pytest.mark.parametrize(
    "value",
    [
        "password=[REDACTED_SECRET]",
        "api key=[REDACTED_SECRET]",
        "secret key=[REDACTED_SECRET]",
        "password=[REDACTED_SECRET]; status=failed",
        "password=[REDACTED_SECRET], status=failed",
        "password=[REDACTED_SECRET] status=failed",
        "password=[REDACTED_SECRET]}",
        "password=[REDACTED_SECRET]]",
        "password=[REDACTED_SECRET]&status=failed",
        "Authorization: Bearer [REDACTED_TOKEN]",
        "Authorization: Basic [REDACTED_TOKEN]",
        "Bearer [REDACTED_TOKEN]; status=failed",
        "Basic [REDACTED_TOKEN], status=failed",
        "Bearer [REDACTED_TOKEN] status=failed",
        "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
        "[REDACTED]",
        "[REDACTED_EMAIL]",
        "[REDACTED_API_KEY]",
        "[REDACTED_PRIVATE_KEY]",
        "[REDACTED_GITHUB_TOKEN]",
        "[REDACTED_AWS_ACCESS_KEY]",
        "[REDACTED_SLACK_TOKEN]",
        "[REDACTED_JWT]",
        "Database connection failed.",
        "Password reset completed.",
        "API key rotation completed.",
    ],
)
def test_legitimate_redaction_markers_preserved(
    value: str,
) -> None:
    validate_outbound_text(value, 2000)


@pytest.mark.parametrize(
    "value",
    [
        f"password=[REDACTED_SECRET] token={CANARY}",
        f"api key=[REDACTED_SECRET] secret key={CANARY}",
        f"Bearer [REDACTED_TOKEN] password={CANARY}",
        f"Basic [REDACTED_TOKEN] api_key={CANARY}",
        (f"postgresql://[REDACTED_CREDENTIALS]@localhost/db password={CANARY}"),
        f"[REDACTED_SECRET] password={CANARY}",
    ],
)
def test_valid_marker_cannot_hide_other_credentials(
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError) as error:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(error.value)
