import pytest
from pydantic import ValidationError

from app.core.config import Settings

LOG_LIMITS = [
    ("log_max_payload_bytes", 1048576, 1024, 10485760),
    ("log_max_entries", 1000, 1, 10000),
    ("log_max_nesting_depth", 32, 1, 128),
    ("log_max_message_chars", 10000, 100, 20000),
    ("log_max_metadata_chars", 500, 32, 2000),
    ("log_max_evidence_entries", 20, 1, 100),
    ("log_max_evidence_chars", 8000, 256, 20000),
]


@pytest.fixture(autouse=True)
def clear_log_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for field, _, _, _ in LOG_LIMITS:
        monkeypatch.delenv(
            field.upper(),
            raising=False,
        )

        monkeypatch.delenv(
            field,
            raising=False,
        )


@pytest.mark.parametrize(
    ("field", "default", "minimum", "maximum"),
    LOG_LIMITS,
)
def test_log_configuration_defaults(
    field: str,
    default: int,
    minimum: int,
    maximum: int,
) -> None:
    settings = Settings(_env_file=None)

    assert getattr(settings, field) == default
    assert minimum <= default <= maximum


@pytest.mark.parametrize(
    ("field", "default", "minimum", "maximum"),
    LOG_LIMITS,
)
def test_log_configuration_minimum(
    field: str,
    default: int,
    minimum: int,
    maximum: int,
) -> None:
    settings = Settings.model_validate({field: minimum})

    assert getattr(settings, field) == minimum


@pytest.mark.parametrize(
    ("field", "default", "minimum", "maximum"),
    LOG_LIMITS,
)
def test_log_configuration_maximum(
    field: str,
    default: int,
    minimum: int,
    maximum: int,
) -> None:
    settings = Settings.model_validate({field: maximum})

    assert getattr(settings, field) == maximum


@pytest.mark.parametrize(
    ("field", "default", "minimum", "maximum"),
    LOG_LIMITS,
)
def test_log_configuration_below_minimum(
    field: str,
    default: int,
    minimum: int,
    maximum: int,
) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({field: minimum - 1})


@pytest.mark.parametrize(
    ("field", "default", "minimum", "maximum"),
    LOG_LIMITS,
)
def test_log_configuration_above_maximum(
    field: str,
    default: int,
    minimum: int,
    maximum: int,
) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({field: maximum + 1})


@pytest.mark.parametrize(
    ("field", "default", "minimum", "maximum"),
    LOG_LIMITS,
)
def test_log_configuration_environment_override(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    default: int,
    minimum: int,
    maximum: int,
) -> None:
    monkeypatch.setenv(
        field.upper(),
        str(maximum),
    )

    settings = Settings(_env_file=None)

    assert getattr(settings, field) == maximum


@pytest.mark.parametrize(
    ("field", "default", "minimum", "maximum"),
    LOG_LIMITS,
)
def test_log_configuration_invalid_environment(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    default: int,
    minimum: int,
    maximum: int,
) -> None:
    monkeypatch.setenv(
        field.upper(),
        "invalid",
    )

    with pytest.raises(ValidationError):
        Settings(_env_file=None)
