"""Rule-based redaction for text and JSON-like report data.

Redaction is enabled by default and lowers common disclosure risks. It is not a
general secret detector, so callers must still limit the data collected.
"""

import base64
import binascii
import json
import re
from html import unescape
from typing import Any
from urllib.parse import unquote

from dev_env_doctor.privacy.policy import (
    _DEVICE_ABSOLUTE_PATH,
    _DRIVE_ABSOLUTE_PATH,
    _PRIVATE_KEY_BLOCK,
    _QUOTED_ABSOLUTE_PATH,
    _QUOTED_USER_DIRECTORY,
    _SENSITIVE_ASSIGNMENT_START,
    _SPACED_ABSOLUTE_PATH,
    _SPACED_TRAILING_ABSOLUTE_PATH,
    _SPACED_TRAILING_USER_DIRECTORY,
    _SPACED_USER_DIRECTORY,
    _UNC_ABSOLUTE_PATH,
    _USER_DIRECTORY,
    MACHINE,
    PATH,
    REDACTED,
    USER_DIR,
    is_sensitive_key,
)

_MAX_INSPECTED_LENGTH = 4096
_MAX_DECODE_ROUNDS = 4
_JSON_STRING = re.compile(r'"(?:[^"\\\x00-\x1f]|\\.)*"')
_JSON_ESCAPED_CHARACTER = re.compile(r'\\(["/])')
_UNICODE_ESCAPE = re.compile(r"\\+u([0-9a-fA-F]{4})")
_BASE64_TOKEN = re.compile(r"(?<![\w+/=-])[A-Za-z0-9_+/-]{8,}={0,2}(?![\w+/=-])")
_PATH_CONTINUATION = re.compile(
    r"(?<=[\\/])(?:[ \t]*\r?\n[ \t]*|[ \t]+(?=\S))"
    r"|(?:[ \t]*\r?\n[ \t]*|[ \t]+)(?=[\\/](?![ \t\\/]))"
    r"|(?<=\S)[ \t]*\r?\n[ \t]*(?=[^ \t\r\n\\/]+[\\/])"
)
_SPACED_DRIVE_PREFIX = re.compile(r"(?<=\b[A-Za-z])[ \t]*:[ \t]*(?=[\\/])")
_EXCEPTION_TEXT = re.compile(
    r"\bTraceback \(most recent call last\):"
    r"|\b(?:[A-Za-z_]\w*)?(?:Error|Exception)[ \t]*[:(]"
)


def _redact_sensitive_assignments(text: str) -> str:
    """Mask recognized assignments without guessing ambiguous value endings.

    Quoted values end only at an unescaped matching quote. An unterminated
    quoted value consumes the remainder. Unquoted values consume through the
    next recognized sensitive assignment, or the remainder if no such
    boundary exists.
    """
    output: list[str] = []
    cursor = 0
    search_from = 0

    while match := _SENSITIVE_ASSIGNMENT_START.search(text, search_from):
        value_start = match.end()
        quote = text[value_start] if value_start < len(text) else ""

        if quote in {"'", '"'}:
            value_end = value_start + 1
            while value_end < len(text):
                if text[value_end] == "\\":
                    value_end += 2
                    continue
                if text[value_end] == quote:
                    value_end += 1
                    break
                value_end += 1
            else:
                output.extend((text[cursor : match.start()], REDACTED))
                return "".join(output)
        else:
            next_assignment = _SENSITIVE_ASSIGNMENT_START.search(text, value_start)
            value_end = next_assignment.start() if next_assignment else len(text)
            if next_assignment:
                while value_end > value_start and text[value_end - 1].isspace():
                    value_end -= 1

        output.extend((text[cursor : match.start()], REDACTED))
        cursor = value_end
        search_from = value_end

    output.append(text[cursor:])
    return "".join(output)


def _redact_plain_text(text: str, machine_names: list[str] | tuple[str, ...]) -> str:
    if _EXCEPTION_TEXT.search(text):
        return REDACTED
    redacted = _PRIVATE_KEY_BLOCK.sub(REDACTED, text)
    redacted = _redact_sensitive_assignments(redacted)
    redacted = _DEVICE_ABSOLUTE_PATH.sub(PATH, redacted)
    redacted = _QUOTED_USER_DIRECTORY.sub(USER_DIR, redacted)
    redacted = _QUOTED_ABSOLUTE_PATH.sub(PATH, redacted)
    redacted = _SPACED_TRAILING_USER_DIRECTORY.sub(USER_DIR, redacted)
    redacted = _SPACED_USER_DIRECTORY.sub(USER_DIR, redacted)
    redacted = _SPACED_ABSOLUTE_PATH.sub(PATH, redacted)
    redacted = _SPACED_TRAILING_ABSOLUTE_PATH.sub(PATH, redacted)
    redacted = _USER_DIRECTORY.sub(USER_DIR, redacted)
    redacted = _DRIVE_ABSOLUTE_PATH.sub(PATH, redacted)
    redacted = _UNC_ABSOLUTE_PATH.sub(PATH, redacted)

    for name in sorted((name for name in machine_names if name), key=len, reverse=True):
        machine_pattern = re.compile(
            rf"(?<![\w.-]){re.escape(name)}(?![\w-]|\.[\w.-])",
            flags=re.IGNORECASE,
        )
        redacted = machine_pattern.sub(MACHINE, redacted)
    return redacted


def _decode_json_string(match: re.Match[str]) -> str:
    token = match[0]
    if "\\" in token:
        try:
            return json.loads(token)
        except ValueError:
            pass
    return token


def _decode_base64(match: re.Match[str]) -> str:
    token = match[0]
    try:
        padded = token + "=" * (-len(token) % 4)
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True).decode("utf-8")
    except (binascii.Error, UnicodeError):
        return token
    if decoded and all(char.isprintable() or char in "\t\r\n" for char in decoded):
        return decoded
    return token


def _needs_conservative_redaction(text: str, machine_names: list[str] | tuple[str, ...]) -> bool:
    # Already recognized assignments have their own quote-aware masking. Preserve
    # the safe text after them instead of decoding inside the masked values.
    candidate = _redact_sensitive_assignments(text)
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unescape(unquote(candidate, errors="replace"))
        decoded = _JSON_STRING.sub(_decode_json_string, decoded)
        decoded = _JSON_ESCAPED_CHARACTER.sub(r"\1", decoded)
        decoded = _UNICODE_ESCAPE.sub(lambda match: chr(int(match[1], 16)), decoded)
        if "\\" * 4 in decoded:
            # Unquoted JSON-escaped UNC prefixes need to retain two separators.
            decoded = decoded.replace("\\\\", "\\")
        decoded = _BASE64_TOKEN.sub(_decode_base64, decoded)
        normalized = _PATH_CONTINUATION.sub("", decoded)
        normalized = _SPACED_DRIVE_PREFIX.sub(":", normalized)
        if "%" in candidate and decoded != candidate:
            normalized = normalized.replace("+", " ")
        if decoded != candidate and _redact_plain_text(decoded, machine_names) != decoded:
            return True
        if normalized != decoded and _redact_plain_text(normalized, machine_names) != normalized:
            return True
        if decoded == candidate:
            return False
        candidate = decoded
    # Continued transformations after the inspection budget are ambiguous.
    return True


def redact_text(text: str, *, machine_names: list[str] | tuple[str, ...] = ()) -> str:
    """Redact known secrets, Windows paths and explicitly supplied machine names.

    Decode only a bounded detection copy. A sensitive encoded or wrapped value
    makes its original field unsafe to retain. Plain text uses targeted masks.
    """
    if len(text) > _MAX_INSPECTED_LENGTH or _needs_conservative_redaction(text, machine_names):
        return REDACTED
    return _redact_plain_text(text, machine_names)


def redact_data(value: Any, *, machine_names: list[str] | tuple[str, ...] = ()) -> Any:
    """Redact strings and sensitive-key values in dictionaries and lists."""
    if isinstance(value, str):
        return redact_text(value, machine_names=machine_names)
    if isinstance(value, dict):
        return {
            key: REDACTED
            if isinstance(key, str) and is_sensitive_key(key)
            else redact_data(item, machine_names=machine_names)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_data(item, machine_names=machine_names) for item in value]
    return value
