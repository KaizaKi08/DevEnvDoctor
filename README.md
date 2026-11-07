# DevEnv Doctor

DevEnv Doctor v0.1.0 is a Windows desktop application for local, read-only checks of developer tools, PATH entries, and Codex configuration metadata. Results are shown in the PySide6 application.

v0.1.0 is a source-only release. The Windows executable package is pending separate license and compatibility acceptance.

## What it checks

- Python, Git, and Node.js discovery and version verification for executables that pass the local trust checks.
- npm and Codex CLI discovery. These checks use file metadata only.
- PATH diagnostics using a bounded snapshot of the desktop process's PATH.
- The presence and safety of the current user's default Codex `config.toml`, using metadata only.

JSON and HTML file export is disabled by default. See the [privacy and security notes](docs/security.md) for what the application reads and how it handles scan data.

## Run from source on Windows

Use Windows 11 x64 with Python 3.13. From the extracted source folder, run these commands in PowerShell.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --index-url https://pypi.org/simple .
.\.venv\Scripts\python.exe -m dev_env_doctor.main
```

Pip obtains PySide6, its Qt and Shiboken dependencies, and Pydantic from PyPI. In the application, choose **开始扫描**. See the [installation and usage guide](docs/installation.md) and the [changelog](CHANGELOG.md).

## Development

The project declares Python 3.11 as its minimum. Windows x64 with Python 3.13 is the development baseline.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -B -m pytest -q -p no:cacheprovider tests/unit
python -B -m ruff check src tests
python -B -m ruff format --check src tests
```

## License

DevEnv Doctor source code is licensed under the [MIT License](LICENSE). Third-party dependencies are available under their respective licenses.
