# Development

## Supported baseline

The initial target is Windows 11 with Python 3.13.9 on 64-bit AMD64. Python 3.11+ is the declared minimum; other versions and architectures require CI and runtime validation before being claimed as supported.

## Local environment

Use a project-local `.venv`. Do not install project dependencies into a global Python environment.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Checks

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

Tests should use simulated commands and temporary fixtures, never real credentials or system modifications. Commands in this document are instructions, not evidence that they have been run.
