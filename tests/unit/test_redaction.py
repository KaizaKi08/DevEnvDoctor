import pytest

from dev_env_doctor.privacy.redaction import redact_data, redact_text


def test_redacts_user_directory_path() -> None:
    assert redact_text(r"Found C:\Users\Alice\Projects\demo") == "Found <USER_DIR>"


def test_redacts_other_absolute_windows_path() -> None:
    assert redact_text("Tool at D:/Apps/Python/python.exe") == "Tool at <PATH>"


@pytest.mark.parametrize(
    ("text", "placeholder", "residue"),
    [
        (
            r'Executable "C:\Users\Alice\My Documents\tool.exe" failed',
            "<USER_DIR>",
            ("Alice", "Documents", "tool.exe"),
        ),
        (
            r"Executable C:\Users\Alice\My Documents\tool.exe failed",
            "<USER_DIR>",
            ("Alice", "Documents", "tool.exe"),
        ),
        (
            r"Executable D:/Apps and Tools/Python/tool.exe failed",
            "<PATH>",
            ("Apps and Tools", "Python", "tool.exe"),
        ),
        (
            r'Executable "//server/share name/tools/tool.exe" failed',
            "<PATH>",
            ("server", "share name", "tool.exe"),
        ),
        (
            r"Found C:\Users\Alice\My Documents",
            "<USER_DIR>",
            ("Alice", "My Documents", "Documents"),
        ),
        (
            r"D:\Apps and Tools",
            "<PATH>",
            ("Apps and Tools", "and Tools"),
        ),
        (
            r"C:\Program Files\Example Tool\tool.exe",
            "<PATH>",
            ("Program Files", "Example Tool", "tool.exe"),
        ),
        (
            r"//server/share name/tools/tool.exe",
            "<PATH>",
            ("server", "share name", "tool.exe"),
        ),
    ],
)
def test_redacts_spaced_quoted_and_unquoted_windows_paths_without_residue(
    text: str, placeholder: str, residue: tuple[str, ...]
) -> None:
    redacted = redact_text(text)

    assert placeholder in redacted
    assert all(fragment not in redacted for fragment in residue)


def test_preserves_relative_paths_and_normal_text_around_spaced_paths() -> None:
    relative = r"My Documents\tool.exe"

    assert redact_text(relative) == relative
    assert redact_text("The tool failed normally.") == "The tool failed normally."


def test_unquoted_path_with_extension_preserves_following_explanation() -> None:
    redacted = redact_text(r"C:\Program Files\Example Tool\tool.exe was checked")

    assert redacted == "<PATH> was checked"


def test_ambiguous_trailing_directory_path_redacts_suffix_conservatively() -> None:
    assert redact_text(r"Found C:\Users\Alice\My Documents") == "Found <USER_DIR>"
    assert redact_text(r"D:\Apps and Tools") == "<PATH>"


def test_preserves_relative_path() -> None:
    relative = r"src\dev_env_doctor\main.py"

    assert redact_text(relative) == relative


def test_windows_path_matching_is_case_insensitive() -> None:
    assert redact_text(r"c:/users/alice/secret.txt") == "<USER_DIR>"
    assert redact_text(r"d:/TOOLS/Python/python.exe") == "<PATH>"


def test_redacts_only_explicitly_supplied_machine_names() -> None:
    text = "Host DevBox-7 found; another host DevBox-8 is unknown."

    assert redact_text(text, machine_names=["devbox-7"]) == (
        "Host <MACHINE> found; another host DevBox-8 is unknown."
    )


def test_machine_name_redaction_preserves_sentence_period_and_other_hostnames() -> None:
    text = "Host DevBox-7. Other names: devbox-7.example.invalid, devbox-70, x.devbox-7."

    assert redact_text(text, machine_names=("devbox-7",)) == (
        "Host <MACHINE>. Other names: devbox-7.example.invalid, devbox-70, x.devbox-7."
    )


def test_redacts_sensitive_values_recursively() -> None:
    value = {
        "access_token": "fake-token-123",
        "nested": [{"Password": "fake-password", "cookie": "fake-cookie"}],
    }

    assert redact_data(value) == {
        "access_token": "<REDACTED>",
        "nested": [{"Password": "<REDACTED>", "cookie": "<REDACTED>"}],
    }


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "apiKey",
        "API_KEY",
        "API-Key",
        "private_key",
        "privateKey",
        "private.key",
        "access_token",
        "access-token",
        "client_secret",
        "clientSecret",
        "AUTHORIZATION",
        "PASSWORD",
        "Cookie",
        "credential_path",
    ],
)
def test_redacts_sensitive_key_variants(key: str) -> None:
    assert redact_data({key: "fictional-secret-value"}) == {key: "<REDACTED>"}


@pytest.mark.parametrize("key", ["key", "key_id", "keyboard", "monkey_count"])
def test_preserves_ordinary_key_fields(key: str) -> None:
    value = "fictional ordinary value"

    assert redact_data({key: value}) == {key: value}


def test_preserves_non_sensitive_text_and_values() -> None:
    value = {"summary": "Python found", "count": 3, "enabled": True}

    assert redact_data(value) == value
    assert redact_text("A normal diagnostic summary.") == "A normal diagnostic summary."


def test_handles_empty_none_and_nested_containers() -> None:
    value = {"empty": "", "missing": None, "items": [None, "", {"secret": None}]}

    assert redact_text("") == ""
    assert redact_data(None) is None
    assert redact_data(value) == {
        "empty": "",
        "missing": None,
        "items": [None, "", {"secret": "<REDACTED>"}],
    }


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=fictional phrase", "<REDACTED>"),
        (
            r'token="fictional\"suffix"; diagnosis complete',
            "<REDACTED>; diagnosis complete",
        ),
        (
            'token="fictional first line\nfictional second line"; diagnosis complete',
            "<REDACTED>; diagnosis complete",
        ),
        ("oauth=fictional_oauth_secret", "<REDACTED>"),
        ("OAUTH=fictional_oauth_secret", "<REDACTED>"),
        ("oauth_status=connected", "oauth_status=connected"),
        ("password=first token=second", "<REDACTED> <REDACTED>"),
        (
            "password='fictional phrase'; ordinary diagnostic text",
            "<REDACTED>; ordinary diagnostic text",
        ),
        (
            'PASSWORD = "fictional phrase"; status=ready',
            "<REDACTED>; status=ready",
        ),
        ("api key = 'fictional_api_value'", "<REDACTED>"),
        (
            "Ordinary diagnostic text without a secret.",
            "Ordinary diagnostic text without a secret.",
        ),
    ],
)
def test_redacts_sensitive_assignments_without_leaking_values_or_losing_safe_suffix(
    text: str, expected: str
) -> None:
    assert redact_text(text) == expected


def test_unquoted_sensitive_value_masks_ambiguous_trailing_text() -> None:
    assert redact_text("password=fictional phrase; ordinary diagnostic text") == "<REDACTED>"
