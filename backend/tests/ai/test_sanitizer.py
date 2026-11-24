import pytest

from app.security import SanitizationResult, sanitize_text


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        (
            "Contact user@example.com for assistance.",
            "Contact [REDACTED_EMAIL] for assistance.",
        ),
        (
            "API credential: sk-proj-1234567890abcdef",
            "API credential: [REDACTED_API_KEY]",
        ),
        (
            "Authorization: Bearer synthetic-token-123",
            "Authorization: Bearer [REDACTED_TOKEN]",
        ),
        (
            "Authorization: Basic dXNlcjpwYXNz",
            "Authorization: Basic [REDACTED_TOKEN]",
        ),
        (
            "password=synthetic-password",
            "password=[REDACTED_SECRET]",
        ),
        (
            "PASSWORD=synthetic-password",
            "PASSWORD=[REDACTED_SECRET]",
        ),
        (
            'password="synthetic password"',
            "password=[REDACTED_SECRET]",
        ),
        (
            "passwd='synthetic password'",
            "passwd=[REDACTED_SECRET]",
        ),
        (
            "pwd: synthetic-password",
            "pwd: [REDACTED_SECRET]",
        ),
        (
            "api_key=synthetic-key",
            "api_key=[REDACTED_SECRET]",
        ),
        (
            "api-key=synthetic-key",
            "api-key=[REDACTED_SECRET]",
        ),
        (
            "access_token=synthetic-token",
            "access_token=[REDACTED_SECRET]",
        ),
        (
            "refresh_token=synthetic-token",
            "refresh_token=[REDACTED_SECRET]",
        ),
        (
            "client_secret=synthetic-secret",
            "client_secret=[REDACTED_SECRET]",
        ),
        (
            "secret_key=synthetic-secret",
            "secret_key=[REDACTED_SECRET]",
        ),
        (
            "token=synthetic-token",
            "token=[REDACTED_SECRET]",
        ),
        (
            "secret=synthetic-secret",
            "secret=[REDACTED_SECRET]",
        ),
        (
            '{"password": "synthetic-secret"}',
            '{"password": [REDACTED_SECRET]}',
        ),
        (
            "postgresql://admin:password@localhost:5432/database",
            "postgresql://[REDACTED_CREDENTIALS]@localhost:5432/database",
        ),
        (
            "mysql://admin:password@localhost/database",
            "mysql://[REDACTED_CREDENTIALS]@localhost/database",
        ),
        (
            "https://admin:password@example.com",
            "https://[REDACTED_CREDENTIALS]@example.com",
        ),
        (
            "JWT: eyJabc123.payload123.signature123",
            "JWT: [REDACTED_JWT]",
        ),
        (
            "-----BEGIN PRIVATE KEY-----\n"
            "SYNTHETIC PRIVATE KEY\n"
            "-----END PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "SYNTHETIC PRIVATE KEY\n"
            "-----END RSA PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
        ),
    ],
)
def test_sensitive_information_redaction(
    original: str,
    expected: str,
) -> None:
    result = sanitize_text(original)

    assert result.text == expected
    assert result.redaction_count == 1
    assert result.was_modified is True


def test_multiple_sensitive_values() -> None:
    result = sanitize_text(
        "User: user@example.com\n"
        "password=synthetic-password\n"
        "Authorization: Bearer synthetic-token"
    )

    assert "user@example.com" not in result.text
    assert "synthetic-password" not in result.text
    assert "synthetic-token" not in result.text
    assert result.redaction_count == 3


def test_technical_information_preserved() -> None:
    original = (
        "HTTP 503 Service Unavailable\n"
        "Database connection timed out.\n"
        "Host: database.internal\n"
        "Port: 5432\n"
        "Error: ConnectionRefusedError\n"
        "Traceback: application.py, line 42"
    )

    result = sanitize_text(original)

    assert result.text == original
    assert result.redaction_count == 0
    assert result.was_modified is False


def test_empty_input() -> None:
    result = sanitize_text("")

    assert result.text == ""
    assert result.redaction_count == 0
    assert result.was_modified is False


def test_unicode_preserved() -> None:
    original = "La aplicación no responde."

    result = sanitize_text(original)

    assert result.text == original


def test_sanitization_is_deterministic() -> None:
    original = "password=synthetic-password"

    assert sanitize_text(original) == sanitize_text(original)


def test_sanitization_result_type() -> None:
    result = sanitize_text("Synthetic incident.")

    assert isinstance(result, SanitizationResult)


def test_repeated_email_addresses() -> None:
    result = sanitize_text("user@example.com and user@example.com")

    assert result.text == ("[REDACTED_EMAIL] and [REDACTED_EMAIL]")
    assert result.redaction_count == 2


def test_non_sensitive_password_reference() -> None:
    original = "The user reported a password reset failure."

    result = sanitize_text(original)

    assert result.text == original
    assert result.redaction_count == 0
