import pytest

from app.security import sanitize_text


@pytest.mark.parametrize(
    "value",
    [
        r'password="synthetic\"hidden-value"',
        r"password='synthetic\'hidden-value'",
        r'{"password": "synthetic\"hidden-value"}',
        r'api_key="synthetic\\hidden-value"',
        'password="synthetic hidden-value',
        "password='synthetic hidden-value",
    ],
)
def test_quoted_secret_redaction(value: str) -> None:
    result = sanitize_text(value)

    assert "synthetic" not in result.text
    assert "hidden-value" not in result.text
    assert "[REDACTED_SECRET]" in result.text
    assert result.redaction_count == 1


@pytest.mark.parametrize(
    ("credential", "replacement"),
    [
        (
            "ghp_" + "a" * 36,
            "[REDACTED_GITHUB_TOKEN]",
        ),
        (
            "gho_" + "b" * 36,
            "[REDACTED_GITHUB_TOKEN]",
        ),
        (
            "github_pat_" + "c" * 40,
            "[REDACTED_GITHUB_TOKEN]",
        ),
        (
            "xoxb-" + "1" * 12 + "-" + "a" * 20,
            "[REDACTED_SLACK_TOKEN]",
        ),
        (
            "AKIA" + "A" * 16,
            "[REDACTED_AWS_ACCESS_KEY]",
        ),
        (
            "ASIA" + "B" * 16,
            "[REDACTED_AWS_ACCESS_KEY]",
        ),
    ],
)
def test_additional_credential_formats(
    credential: str,
    replacement: str,
) -> None:
    result = sanitize_text(f"Synthetic credential: {credential}")

    assert credential not in result.text
    assert replacement in result.text
    assert result.redaction_count == 1


def test_quoted_secret_preserves_following_text() -> None:
    result = sanitize_text(r'password="synthetic\"hidden-value"; status=failed')

    assert result.text == ("password=[REDACTED_SECRET]; status=failed")


def test_multiple_credential_formats() -> None:
    github_token = "ghp_" + "a" * 36
    aws_key = "AKIA" + "B" * 16

    result = sanitize_text(
        f"Credential A: {github_token}; "
        f"Credential B: {aws_key}; "
        "Contact: user@example.com"
    )

    assert github_token not in result.text
    assert aws_key not in result.text
    assert "user@example.com" not in result.text
    assert result.redaction_count == 3


def test_unterminated_secret_preserves_next_line() -> None:
    result = sanitize_text('password="synthetic-secret\nDatabase connection failed.')

    assert result.text == ("password=[REDACTED_SECRET]\nDatabase connection failed.")


def test_technical_identifiers_preserved() -> None:
    value = (
        "GitHub repository unavailable. "
        "AWS database connection failed. "
        "Slack notification delayed. "
        "HTTP 503."
    )

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0
    assert result.was_modified is False
