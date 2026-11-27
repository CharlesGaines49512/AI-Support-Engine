import re

from app.parsers.exceptions import (
    InvalidLogEncodingError,
    UnsafeLogContentError,
)

PRIVATE_KEY_BOUNDARY = re.compile(
    r"-----\s*(BEGIN|END)\s+"
    r"([A-Z0-9 ]*PRIVATE KEY)\s*-----",
    re.IGNORECASE,
)

CREDENTIAL_LABELS = (
    "[p\\uff50][a\\uff41][s\\uff53]["
    "s\\uff53][w\\uff57][o\\uff4f][r"
    "\\uff52][d\\uff44]|[p\\uff50][a"
    "\\uff41][s\\uff53][s\\uff53][w\\"
    "uff57][d\\uff44]|[p\\uff50][w\\"
    "uff57][d\\uff44]|[s\\uff53][e\\"
    "uff45][c\\uff43][r\\uff52][e\\u"
    "ff45][t\\uff54]|[a\\uff41][p\\u"
    "ff50][i\\uff49][_ \\-\\u00a0\\u1"
    "680\\u2000-\\u200a\\u202f\\u205f"
    "\\u3000\\uff3f\\uff0d]*[k\\uff4b"
    "][e\\uff45][y\\uff59]|[a\\uff41"
    "][c\\uff43][c\\uff43][e\\uff45]"
    "[s\\uff53][s\\uff53][_ \\-\\u00a"
    "0\\u1680\\u2000-\\u200a\\u202f\\u"
    "205f\\u3000\\uff3f\\uff0d]*[t\\u"
    "ff54][o\\uff4f][k\\uff4b][e\\uf"
    "f45][n\\uff4e]|[r\\uff52][e\\uf"
    "f45][f\\uff46][r\\uff52][e\\uff"
    "45][s\\uff53][h\\uff48][_ \\-\\u"
    "00a0\\u1680\\u2000-\\u200a\\u202"
    "f\\u205f\\u3000\\uff3f\\uff0d]*["
    "t\\uff54][o\\uff4f][k\\uff4b][e"
    "\\uff45][n\\uff4e]|[c\\uff43][l"
    "\\uff4c][i\\uff49][e\\uff45][n\\"
    "uff4e][t\\uff54][_ \\-\\u00a0\\u"
    "1680\\u2000-\\u200a\\u202f\\u205"
    "f\\u3000\\uff3f\\uff0d]*[s\\uff5"
    "3][e\\uff45][c\\uff43][r\\uff52"
    "][e\\uff45][t\\uff54]|[s\\uff53"
    "][e\\uff45][c\\uff43][r\\uff52]"
    "[e\\uff45][t\\uff54][_ \\-\\u00a"
    "0\\u1680\\u2000-\\u200a\\u202f\\u"
    "205f\\u3000\\uff3f\\uff0d]*[k\\u"
    "ff4b][e\\uff45][y\\uff59]|[t\\u"
    "ff54][o\\uff4f][k\\uff4b][e\\uf"
    "f45][n\\uff4e]|[a\\uff41][u\\uf"
    "f55][t\\uff54][h\\uff48][o\\uff"
    "4f][r\\uff52][i\\uff49][z\\uff5"
    "a][a\\uff41][t\\uff54][i\\uff49"
    "][o\\uff4f][n\\uff4e]|[c\\uff43"
    "][r\\uff52][e\\uff45][d\\uff44]"
    "[e\\uff45][n\\uff4e][t\\uff54]["
    "i\\uff49][a\\uff41][l\\uff4c]"
)

INCOMPLETE_ASSIGNMENT = re.compile(
    (
        "(?:^|[\\s,;{])[\"']?(?:"
        f"{CREDENTIAL_LABELS}"
        ")[\"']?[\\t \\u00a0\\u1680\\u2000-\\"
        "u200a\\u202f\\u205f\\u3000]*[:=\\u"
        "ff1a\\uff1d\\ufe55\\ufe66][\\t \\u0"
        "0a0\\u1680\\u2000-\\u200a\\u202f\\u"
        "205f\\u3000]*[\"']?[\\t \\u00a0\\u1"
        "680\\u2000-\\u200a\\u202f\\u205f\\u"
        "3000]*$"
    ),
    re.IGNORECASE | re.MULTILINE,
)

INCOMPLETE_AUTHORIZATION = re.compile(
    (
        "(?:^|\\s)(?:authorization\\s*:\\s"
        "*)?(?:[b\\uff42][e\\uff45][a\\uff"
        "41][r\\uff52][e\\uff45][r\\uff52]"
        "|[b\\uff42][a\\uff41][s\\uff53][i"
        "\\uff49][c\\uff43])[\\t \\u00a0\\u1"
        "680\\u2000-\\u200a\\u202f\\u205f\\u"
        "3000]*$"
    ),
    re.IGNORECASE | re.MULTILINE,
)

STANDALONE_CREDENTIAL_LABEL = re.compile(
    rf"""["']?(?:{CREDENTIAL_LABELS})["']?""",
    re.IGNORECASE,
)


UNSUPPORTED_FORMAT_CONTROLS = frozenset(
    {
        0x00AD,
        0x061C,
        0x200B,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2060,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0xFEFF,
    }
)


JOINER_CREDENTIAL_PATTERN = re.compile(
    (
        "(?<!\\w)(?:[p\\uff50][\\u200c\\u"
        "200d]*[a\\uff41][\\u200c\\u200d"
        "]*[s\\uff53][\\u200c\\u200d]*[s"
        "\\uff53][\\u200c\\u200d]*[w\\uff"
        "57][\\u200c\\u200d]*[o\\uff4f]["
        "\\u200c\\u200d]*[r\\uff52][\\u20"
        "0c\\u200d]*[d\\uff44]|[p\\uff50"
        "][\\u200c\\u200d]*[a\\uff41][\\u"
        "200c\\u200d]*[s\\uff53][\\u200c"
        "\\u200d]*[s\\uff53][\\u200c\\u20"
        "0d]*[w\\uff57][\\u200c\\u200d]*"
        "[d\\uff44]|[p\\uff50][\\u200c\\u"
        "200d]*[w\\uff57][\\u200c\\u200d"
        "]*[d\\uff44]|[a\\uff41][\\u200c"
        "\\u200d]*[p\\uff50][\\u200c\\u20"
        "0d]*[i\\uff49][_ \\-\\u00a0\\u16"
        "80\\u2000-\\u200a\\u202f\\u205f\\"
        "u3000\\uff3f\\uff0d\\u200c\\u200"
        "d]*[k\\uff4b][\\u200c\\u200d]*["
        "e\\uff45][\\u200c\\u200d]*[y\\uf"
        "f59]|[a\\uff41][\\u200c\\u200d]"
        "*[c\\uff43][\\u200c\\u200d]*[c\\"
        "uff43][\\u200c\\u200d]*[e\\uff4"
        "5][\\u200c\\u200d]*[s\\uff53][\\"
        "u200c\\u200d]*[s\\uff53][_ \\-\\"
        "u00a0\\u1680\\u2000-\\u200a\\u20"
        "2f\\u205f\\u3000\\uff3f\\uff0d\\u"
        "200c\\u200d]*[t\\uff54][\\u200c"
        "\\u200d]*[o\\uff4f][\\u200c\\u20"
        "0d]*[k\\uff4b][\\u200c\\u200d]*"
        "[e\\uff45][\\u200c\\u200d]*[n\\u"
        "ff4e]|[r\\uff52][\\u200c\\u200d"
        "]*[e\\uff45][\\u200c\\u200d]*[f"
        "\\uff46][\\u200c\\u200d]*[r\\uff"
        "52][\\u200c\\u200d]*[e\\uff45]["
        "\\u200c\\u200d]*[s\\uff53][\\u20"
        "0c\\u200d]*[h\\uff48][_ \\-\\u00"
        "a0\\u1680\\u2000-\\u200a\\u202f\\"
        "u205f\\u3000\\uff3f\\uff0d\\u200"
        "c\\u200d]*[t\\uff54][\\u200c\\u2"
        "00d]*[o\\uff4f][\\u200c\\u200d]"
        "*[k\\uff4b][\\u200c\\u200d]*[e\\"
        "uff45][\\u200c\\u200d]*[n\\uff4"
        "e]|[c\\uff43][\\u200c\\u200d]*["
        "l\\uff4c][\\u200c\\u200d]*[i\\uf"
        "f49][\\u200c\\u200d]*[e\\uff45]"
        "[\\u200c\\u200d]*[n\\uff4e][\\u2"
        "00c\\u200d]*[t\\uff54][_ \\-\\u0"
        "0a0\\u1680\\u2000-\\u200a\\u202f"
        "\\u205f\\u3000\\uff3f\\uff0d\\u20"
        "0c\\u200d]*[s\\uff53][\\u200c\\u"
        "200d]*[e\\uff45][\\u200c\\u200d"
        "]*[c\\uff43][\\u200c\\u200d]*[r"
        "\\uff52][\\u200c\\u200d]*[e\\uff"
        "45][\\u200c\\u200d]*[t\\uff54]|"
        "[s\\uff53][\\u200c\\u200d]*[e\\u"
        "ff45][\\u200c\\u200d]*[c\\uff43"
        "][\\u200c\\u200d]*[r\\uff52][\\u"
        "200c\\u200d]*[e\\uff45][\\u200c"
        "\\u200d]*[t\\uff54][_ \\-\\u00a0"
        "\\u1680\\u2000-\\u200a\\u202f\\u2"
        "05f\\u3000\\uff3f\\uff0d\\u200c\\"
        "u200d]*[k\\uff4b][\\u200c\\u200"
        "d]*[e\\uff45][\\u200c\\u200d]*["
        "y\\uff59]|[t\\uff54][\\u200c\\u2"
        "00d]*[o\\uff4f][\\u200c\\u200d]"
        "*[k\\uff4b][\\u200c\\u200d]*[e\\"
        "uff45][\\u200c\\u200d]*[n\\uff4"
        "e]|[s\\uff53][\\u200c\\u200d]*["
        "e\\uff45][\\u200c\\u200d]*[c\\uf"
        "f43][\\u200c\\u200d]*[r\\uff52]"
        "[\\u200c\\u200d]*[e\\uff45][\\u2"
        "00c\\u200d]*[t\\uff54]|[a\\uff4"
        "1][\\u200c\\u200d]*[u\\uff55][\\"
        "u200c\\u200d]*[t\\uff54][\\u200"
        "c\\u200d]*[h\\uff48][\\u200c\\u2"
        "00d]*[o\\uff4f][\\u200c\\u200d]"
        "*[r\\uff52][\\u200c\\u200d]*[i\\"
        "uff49][\\u200c\\u200d]*[z\\uff5"
        "a][\\u200c\\u200d]*[a\\uff41][\\"
        "u200c\\u200d]*[t\\uff54][\\u200"
        "c\\u200d]*[i\\uff49][\\u200c\\u2"
        "00d]*[o\\uff4f][\\u200c\\u200d]"
        "*[n\\uff4e]|[c\\uff43][\\u200c\\"
        "u200d]*[r\\uff52][\\u200c\\u200"
        "d]*[e\\uff45][\\u200c\\u200d]*["
        "d\\uff44][\\u200c\\u200d]*[e\\uf"
        "f45][\\u200c\\u200d]*[n\\uff4e]"
        "[\\u200c\\u200d]*[t\\uff54][\\u2"
        "00c\\u200d]*[i\\uff49][\\u200c\\"
        "u200d]*[a\\uff41][\\u200c\\u200"
        "d]*[l\\uff4c])(?!\\w)[\\u200c\\u"
        "200d]*[\"']?\\s*[:=\\uff1a\\uff1"
        "d\\ufe55\\ufe66]"
    ),
    re.IGNORECASE,
)


JOINER_AUTHORIZATION_PATTERN = re.compile(
    (
        "(?<!\\w)(?=[A-Za-z\\uff21-\\uff"
        "3a\\uff41-\\uff5a]*[\\u200c\\u20"
        "0d])(?:[b\\uff42][\\u200c\\u200"
        "d]*[e\\uff45][\\u200c\\u200d]*["
        "a\\uff41][\\u200c\\u200d]*[r\\uf"
        "f52][\\u200c\\u200d]*[e\\uff45]"
        "[\\u200c\\u200d]*[r\\uff52]|[b\\"
        "uff42][\\u200c\\u200d]*[a\\uff4"
        "1][\\u200c\\u200d]*[s\\uff53][\\"
        "u200c\\u200d]*[i\\uff49][\\u200"
        "c\\u200d]*[c\\uff43])[\\u200c\\u"
        "200d]*(?!\\w)"
    ),
    re.IGNORECASE,
)


def validate_sensitive_field(value: str) -> None:
    """Reject recognizable credential fragments and unsafe characters."""

    # Standardize line endings for security inspection only.
    value = value.replace("\r\n", "\n").replace("\r", "\n")

    if any(
        (ord(character) < 32 and character not in "\t\r\n")
        or 127 <= ord(character) <= 159
        or 0xD800 <= ord(character) <= 0xDFFF
        or ord(character) in UNSUPPORTED_FORMAT_CONTROLS
        for character in value
    ):
        raise InvalidLogEncodingError("Log field contains unsupported characters.")

    if any(
        "\u200c" in match.group() or "\u200d" in match.group()
        for match in JOINER_CREDENTIAL_PATTERN.finditer(value)
    ):
        raise UnsafeLogContentError(
            "Log field contains an obfuscated credential expression."
        )

    if JOINER_AUTHORIZATION_PATTERN.search(value) is not None:
        raise UnsafeLogContentError(
            "Log field contains an obfuscated authorization expression."
        )

    active_key: str | None = None

    for boundary in PRIVATE_KEY_BOUNDARY.finditer(value):
        direction = boundary.group(1).upper()
        key_type = boundary.group(2).upper()

        if direction == "BEGIN":
            if active_key is not None:
                raise UnsafeLogContentError(
                    "Log field contains fragmented private key material."
                )

            active_key = key_type

        else:
            if active_key != key_type:
                raise UnsafeLogContentError(
                    "Log field contains fragmented private key material."
                )

            active_key = None

    if active_key is not None:
        raise UnsafeLogContentError(
            "Log field contains fragmented private key material."
        )

    if (
        INCOMPLETE_ASSIGNMENT.search(value)
        or INCOMPLETE_AUTHORIZATION.search(value)
        or STANDALONE_CREDENTIAL_LABEL.fullmatch(value.strip())
    ):
        raise UnsafeLogContentError(
            "Log field contains an incomplete credential expression."
        )
