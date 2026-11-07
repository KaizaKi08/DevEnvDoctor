# Install and use DevEnv Doctor 0.1.0

## Windows 11 x64

1. Install Python 3.13 x64 with the Windows Python launcher.
2. Extract the v0.1.0 source archive to a local fixed drive and open PowerShell in that folder.
3. Create a virtual environment, install the project and its dependencies from PyPI, and start the GUI.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --index-url https://pypi.org/simple .
.\.venv\Scripts\python.exe -m dev_env_doctor.main
```

Choose **开始扫描** and review the results. The **技术诊断** section shows scan progress and completion details. The Windows executable package is pending separate acceptance.

## Read the results

- A discovered executable may be reported without a version if it cannot pass verification. Python, Git, and Node.js version checks require a trusted executable. npm and Codex CLI show discovery status.
- PATH entries on unsupported or unverifiable volumes are skipped. The scan uses the PATH inherited by the GUI at launch, so restart the application after changing PATH.
- The Codex configuration check reports whether the default file exists and whether its location and metadata can be verified. Details about accounts, authentication, and configuration contents are outside the scan.
- JSON and HTML export remains disabled. Results can be reviewed in the application.
