import ctypes
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest

from dev_env_doctor.collectors import known_folders


@pytest.fixture
def shell(monkeypatch):
    observed = []
    buffers = []

    def lookup(guid, flags, token, result):
        observed.append((UUID(bytes_le=bytes(guid._obj)), flags, token))
        index = len(observed)
        buffer = ctypes.create_unicode_buffer(rf"C:\Synthetic Program Files {index}")
        buffers.append(buffer)
        result._obj.value = ctypes.addressof(buffer)
        return 0 if index != 2 else -2147467259

    ole32 = SimpleNamespace(
        CoInitializeEx=Mock(return_value=1),
        CoUninitialize=Mock(),
        CoTaskMemFree=Mock(),
    )
    shell32 = SimpleNamespace(SHGetKnownFolderPath=Mock(side_effect=lookup))
    libraries = {"ole32": ole32, "shell32": shell32}
    monkeypatch.setattr(known_folders, "os", SimpleNamespace(name="nt"))
    loader = Mock(side_effect=lambda name, **_options: libraries[name])
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    return SimpleNamespace(
        ole32=ole32, shell32=shell32, observed=observed, buffers=buffers, loader=loader
    )


@pytest.mark.parametrize("pointer_size", [4, 8], ids=["wow64", "x64"])
def test_only_fixed_program_files_ids_with_default_no_verify_flags(
    shell, monkeypatch, pointer_size
):
    sizeof = ctypes.sizeof
    monkeypatch.setattr(
        ctypes, "sizeof", lambda value: pointer_size if value is ctypes.c_void_p else sizeof(value)
    )
    roots = known_folders.program_files_folders()

    ids = [
        UUID("905e63b6-c1bf-494e-b29c-65b732d3d21a"),
        UUID("7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e"),
    ]
    if pointer_size == 8:
        ids.append(UUID("6d809377-6af0-444b-8957-a3773f02200e"))
    assert shell.observed == [(guid, 0x4400, None) for guid in ids]
    assert [call.kwargs["winmode"] for call in shell.loader.call_args_list] == [0x800, 0x800]
    expected = (r"C:\Synthetic Program Files 1",)
    if pointer_size == 8:
        expected += (r"C:\Synthetic Program Files 3",)
    assert roots == expected
    shell.ole32.CoInitializeEx.assert_called_once_with(None, 0)
    shell.ole32.CoUninitialize.assert_called_once_with()
    assert [args.args[0].value for args in shell.ole32.CoTaskMemFree.call_args_list] == [
        ctypes.addressof(buffer) for buffer in shell.buffers
    ]


def test_known_folder_com_failure_fails_closed(shell):
    shell.ole32.CoInitializeEx.return_value = -2147417850
    assert known_folders.program_files_folders() == ()
    shell.shell32.SHGetKnownFolderPath.assert_not_called()
    shell.ole32.CoUninitialize.assert_not_called()
    shell.ole32.CoTaskMemFree.assert_not_called()


def test_profile_resolves_current_user_without_verifying_filesystem(shell):
    assert known_folders.user_profile_folder() == r"C:\Synthetic Program Files 1"
    assert shell.observed == [(UUID("5e6c858f-0e22-4760-9afe-ea3317b67173"), 0x4000, None)]
    shell.ole32.CoTaskMemFree.assert_called_once()
    shell.ole32.CoUninitialize.assert_called_once()
