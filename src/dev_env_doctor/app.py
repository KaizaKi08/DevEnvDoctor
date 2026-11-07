"""Qt application startup and composition boundary."""

import sys
from collections.abc import Sequence

from PySide6.QtWidgets import QApplication

from dev_env_doctor.gui.main_window import MainWindow


def _create_main_window() -> MainWindow:
    """Create the desktop window without starting diagnostics."""
    return MainWindow()


def run_gui(argv: Sequence[str] | None = None) -> int:
    """Create or reuse the Qt application, show the window, and run its loop."""
    application = QApplication.instance()
    if application is None:
        application = QApplication(sys.argv if argv is None else list(argv))

    window = _create_main_window()
    window.show()
    return application.exec()
