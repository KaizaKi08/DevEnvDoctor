"""Stable command-line entry point for the desktop application."""

from dev_env_doctor.app import run_gui


def main() -> int:
    """Delegate application startup to the Qt composition layer."""
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
