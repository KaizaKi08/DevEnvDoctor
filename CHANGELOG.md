# Changelog

## v0.1.0

Source-only release.

- Added a Windows desktop interface for local diagnostics and Worker lifecycle status.
- Added bounded PATH discovery and trusted version checks for Python, Git, and Node.js. npm and Codex CLI checks are discovery-only.
- Added a metadata-only audit of the default Codex configuration file.
- Added fail-closed volume checks and separate restricted environments for the Worker and tool subprocesses.
- Added shared privacy filtering for GUI and reports. JSON and HTML file export remains disabled by default.
