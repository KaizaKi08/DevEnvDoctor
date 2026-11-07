"""Explicit, rule-based privacy filters for diagnostic report data.

These rules reduce common disclosure risks; they cannot identify every secret.
"""

import re

REDACTED = "<REDACTED>"
USER_DIR = "<USER_DIR>"
PATH = "<PATH>"
MACHINE = "<MACHINE>"

_SENSITIVE_KEY_PARTS = frozenset(
    {
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "oauth",
        "password",
        "passwd",
        "privatekey",
        "secret",
        "token",
    }
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    flags=re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_ASSIGNMENT_START = re.compile(
    r"(?i)(?<![\w])(?:api[ \t._-]*key|private[ \t._-]*key|"
    r"access[ \t._-]*token|refresh[ \t._-]*token|client[ \t._-]*secret|"
    r"authorization|auth|credential(?:s)?|password|passwd|secret|token|cookie|oauth)"
    r"(?![\w])['\"]?\s*[:=]\s*"
)
_USER_DIRECTORY = re.compile(
    r"(?i)(?<![\w])([a-z]:[\\/]+users[\\/]+[^\\/\s<>:\"|?*]+)(?:[\\/][^\s<>\"']*)?"
)
_QUOTED_USER_DIRECTORY = re.compile(
    r"""(?i)(?<![\w])(?P<quote>["'])([a-z]:[\\/]+users[\\/]+[^"'<>\r\n]*?)(?P=quote)"""
)
_QUOTED_ABSOLUTE_PATH = re.compile(
    r"""(?i)(?P<quote>["'])(?:[a-z]:[\\/]|(?:\\\\|//)[^\\/\s<>:"|?*]+[\\/])[^"'<>\r\n]*?(?P=quote)"""
)
_DEVICE_PREFIX = r"(?:[\\/]{2}[?.][\\/]|[\\/]\?\?[\\/]|[\\/]Device[\\/])"
_DEVICE_ABSOLUTE_PATH = re.compile(
    rf"""(?i)(?<![\w\\/])(?:"{_DEVICE_PREFIX}[^"<>\r\n]*"|'{_DEVICE_PREFIX}[^'<>\r\n]*'|{_DEVICE_PREFIX}[^"'<>\r\n]*)"""
)
_SPACED_USER_DIRECTORY = re.compile(
    r"(?i)(?<![\w])[a-z]:[\\/]+users[\\/]+[^\\/<>:\"|?*]+"
    r"(?:[\\/][^<>:\"|?*\r\n]*?)?\.[a-z0-9]{1,10}(?=$|[\s,;)\]])"
)
_SPACED_TRAILING_USER_DIRECTORY = re.compile(
    r"(?im)(?<![\w])[a-z]:[\\/]+users[\\/]+[^<>:\"|?*\r\n]*"
    r"[ \t][^<>:\"|?*\r\n]*(?=\r?$)"
)
_SPACED_ABSOLUTE_PATH = re.compile(
    r"(?i)(?<![\w:])(?:[a-z]:[\\/]|(?:\\\\|//)[^\\/\s<>:\"|?*]+"
    r"[\\/][^\\/<>:\"|?*]+[\\/])[^<>:\"|?*\r\n]*?"
    r"\.[a-z0-9]{1,10}(?=$|[\s,;)\]])"
)
_SPACED_TRAILING_ABSOLUTE_PATH = re.compile(
    r"(?im)(?<![\w:])(?:[a-z]:[\\/]+|(?:\\\\|//)[^\\/\s<>:\"|?*]+[\\/])"
    r"[^<>:\"|?*\r\n]*[ \t][^<>:\"|?*\r\n]*(?=\r?$)"
)
_DRIVE_ABSOLUTE_PATH = re.compile(r"(?i)(?<![\w:])[a-z]:[\\/]+[^\s<>\"']+")
_UNC_ABSOLUTE_PATH = re.compile(
    r"(?<![\w])(?:\\\\|//)[^\\/\s<>:\"|?*]+[\\/][^\\/\s<>:\"|?*]+(?:[\\/][^\s<>\"']*)?"
)


def is_sensitive_key(key: str) -> bool:
    """Return whether a key contains a known sensitive field name."""
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    parts = re.findall(r"[a-z0-9]+", separated.lower())
    if any(part in _SENSITIVE_KEY_PARTS for part in parts):
        return True
    return any(
        pair in {("api", "key"), ("private", "key")} for pair in zip(parts, parts[1:], strict=False)
    )
