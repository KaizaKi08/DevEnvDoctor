from __future__ import annotations

import importlib
import runpy
import sys
from unittest.mock import Mock

import pytest

import dev_env_doctor.app as app_module
import dev_env_doctor.main as main_module
from dev_env_doctor.core import runner
from dev_env_doctor.gui import main_window as main_window_module


class FakeApplication:
    active: FakeApplication | None = None
    constructions: list[list[str]] = []
    exec_calls = 0
    exit_code = 17

    def __init__(self, argv: list[str]) -> None:
        type(self).constructions.append(argv)
        type(self).active = self

    def exec(self) -> int:
        type(self).exec_calls += 1
        return type(self).exit_code

    @classmethod
    def instance(cls) -> FakeApplication | None:
        return cls.active


def setup_function() -> None:
    FakeApplication.active = None
    FakeApplication.constructions = []
    FakeApplication.exec_calls = 0
    FakeWindow.instances = []


class FakeWindow:
    instances: list[FakeWindow] = []

    def __init__(self) -> None:
        self.show_calls = 0
        type(self).instances.append(self)

    def show(self) -> None:
        self.show_calls += 1


def test_main_delegates_to_run_gui_and_returns_its_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_gui = Mock(return_value=23)
    monkeypatch.setattr(main_module, "run_gui", run_gui)

    assert main_module.main() == 23
    run_gui.assert_called_once_with()


def test_run_gui_uses_process_arguments_when_argv_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_argv = ["dev-env-doctor", "--example"]
    monkeypatch.setattr(app_module, "QApplication", FakeApplication)
    monkeypatch.setattr(app_module, "MainWindow", FakeWindow)
    monkeypatch.setattr(app_module.sys, "argv", process_argv)

    exit_code = app_module.run_gui()

    assert exit_code == FakeApplication.exit_code
    assert FakeApplication.constructions == [process_argv]
    assert len(FakeWindow.instances) == 1
    assert FakeWindow.instances[0].show_calls == 1
    assert FakeApplication.exec_calls == 1


def test_run_gui_passes_explicit_arguments_and_reuses_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "QApplication", FakeApplication)
    monkeypatch.setattr(app_module, "MainWindow", FakeWindow)
    explicit_argv = ("test-app", "--safe-mode")

    first_exit_code = app_module.run_gui(explicit_argv)
    first_instance = FakeApplication.active
    second_exit_code = app_module.run_gui(["ignored-second-argv"])

    assert first_exit_code == FakeApplication.exit_code
    assert second_exit_code == FakeApplication.exit_code
    assert FakeApplication.constructions == [["test-app", "--safe-mode"]]
    assert FakeApplication.active is first_instance
    assert len(FakeWindow.instances) == 2
    assert all(window.show_calls == 1 for window in FakeWindow.instances)
    assert FakeApplication.exec_calls == 2


def test_run_gui_reuses_an_already_existing_qapplication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing_application = Mock()
    existing_application.exec.return_value = 29
    application_type = Mock()
    application_type.instance.return_value = existing_application
    monkeypatch.setattr(app_module, "MainWindow", FakeWindow)
    monkeypatch.setattr(app_module, "QApplication", application_type)

    exit_code = app_module.run_gui(["explicit-app"])

    assert exit_code == 29
    application_type.instance.assert_called_once_with()
    application_type.assert_not_called()
    assert existing_application.exec.call_count == 1
    assert FakeWindow.instances[-1].show_calls == 1


def test_importing_entry_modules_does_not_start_qt_or_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qt_widgets = importlib.import_module("PySide6.QtWidgets")
    original_app_window_factory = app_module.MainWindow
    original_window_type = main_window_module.MainWindow
    original_application_type = app_module.QApplication
    application_type = Mock()
    window_factory = Mock()
    scan = Mock(side_effect=AssertionError("scan must not run during import"))

    monkeypatch.setattr(qt_widgets, "QApplication", application_type)
    monkeypatch.setattr(runner, "run_scan", scan)
    monkeypatch.setattr(main_window_module, "MainWindow", window_factory)

    try:
        importlib.reload(app_module)
        importlib.reload(main_module)
        module = importlib.import_module("dev_env_doctor.__main__")
        importlib.reload(module)

        application_type.assert_not_called()
        application_type.instance.assert_not_called()
        window_factory.assert_not_called()
        scan.assert_not_called()
    finally:
        app_module.QApplication = original_application_type
        app_module.MainWindow = original_app_window_factory
        main_window_module.MainWindow = original_window_type


def test_module_entrypoint_raises_system_exit_with_main_return_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main_module, "main", lambda: 31)
    module_name = "dev_env_doctor.__main__"
    previous_module = sys.modules.pop(module_name, None)

    try:
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module(module_name, run_name="__main__")
    finally:
        sys.modules.pop(module_name, None)
        if previous_module is not None:
            sys.modules[module_name] = previous_module

    assert exc_info.value.code == 31
