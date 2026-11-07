"""Explicit, privacy-safe environments for supervised child processes."""

import ntpath
import os
from collections.abc import Mapping

from dev_env_doctor.collectors.environment import _local_directory_state


class EnvironmentConstructionError(ValueError):
    """Raised when a required child-process environment value is unsafe."""


_ALLOWED_NAMES = frozenset({"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"})
PROBE_UNICODE_NAME = "DEVENV_DOCTOR_PROBE_UNICODE"
PROBE_UNICODE_VALUE = "DevEnvDoctor-环境-✓"


def _value(environment: Mapping[str, str], name: str) -> str | None:
    matches = [(key, value) for key, value in environment.items() if key.upper() == name]
    if not matches:
        return None
    if len(matches) != 1:
        raise EnvironmentConstructionError()
    values = {value for _, value in matches}
    if len(values) != 1:
        raise EnvironmentConstructionError()
    return matches[0][1]


def _safe_local_directory(value: str | None) -> str:
    if not isinstance(value, str) or not ntpath.isabs(value):
        raise EnvironmentConstructionError()
    normalized = ntpath.normpath(value)
    if normalized.startswith("\\\\") or _local_directory_state(normalized) is not True:
        raise EnvironmentConstructionError()
    return normalized


def _system_values(source: Mapping[str, str]) -> dict[str, str]:
    system_root = _value(source, "SYSTEMROOT")
    windir = _value(source, "WINDIR")
    if system_root is None or windir is None:
        raise EnvironmentConstructionError()
    safe_root = _safe_local_directory(system_root)
    safe_windir = _safe_local_directory(windir)
    if ntpath.normcase(safe_root) != ntpath.normcase(safe_windir):
        raise EnvironmentConstructionError()
    return {"SystemRoot": safe_root, "WINDIR": safe_windir}


def _safe_temp_values(source: Mapping[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("TEMP", "TMP"):
        value = _value(source, name)
        if value is None:
            raise EnvironmentConstructionError()
        result[name] = _safe_local_directory(value)
    return result


def _safe_path(system_root: str, extra_directory: str | None = None) -> str:
    entries = [ntpath.join(system_root, "System32"), system_root]
    if extra_directory is not None:
        extra = _safe_local_directory(extra_directory)
        if extra not in entries:
            entries.insert(0, extra)
    return ";".join(entries)


def build_worker_environment(
    source: Mapping[str, str] | None = None, *, include_probe_marker: bool = False
) -> dict[str, str]:
    """Build the minimal environment passed from GUI/service to Worker."""
    source = os.environ if source is None else source
    values = _system_values(source)
    values.update(_safe_temp_values(source))
    values["PATH"] = _safe_path(values["SystemRoot"])
    if include_probe_marker:
        values[PROBE_UNICODE_NAME] = PROBE_UNICODE_VALUE
    return values


def build_tool_environment(
    executable: str,
    source: Mapping[str, str] | None = None,
    *,
    include_probe_marker: bool = False,
) -> dict[str, str]:
    """Build a minimal tool environment without inheriting user configuration."""
    if not isinstance(executable, str) or not ntpath.isabs(executable):
        raise EnvironmentConstructionError()
    source = os.environ if source is None else source
    values = build_worker_environment(source, include_probe_marker=include_probe_marker)
    values["PATH"] = _safe_path(values["SystemRoot"], ntpath.dirname(executable))
    return values
