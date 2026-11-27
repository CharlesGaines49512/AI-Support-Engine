import re
from datetime import UTC, datetime

TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ]"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:[.,][0-9]{1,6})?"
    r"(?P<timezone>Z|[+-][0-9]{2}:?[0-9]{2})"
)


def normalize_timestamp(
    timestamp: str | None,
) -> datetime | None:
    """Normalize supported timestamps into timezone-aware UTC."""

    if timestamp is None:
        return None

    value = timestamp.strip()

    match = TIMESTAMP_PATTERN.fullmatch(value)

    if match is None:
        return None

    timezone = match.group("timezone")

    if timezone != "Z":
        offset = timezone[1:].replace(":", "")

        hours = int(offset[:2])
        minutes = int(offset[2:])

        if hours > 23 or minutes > 59:
            return None

        if timezone.startswith("-") and hours == 0 and minutes == 0:
            return None

    try:
        parsed = datetime.fromisoformat(value)

        return parsed.astimezone(UTC)

    except ValueError, OverflowError:
        return None
