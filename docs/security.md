# Security and privacy

DevEnv Doctor performs local, read-only diagnostics. Scans leave PATH, the registry, system settings, and user configuration files untouched. Scan data stays on the machine.

## Diagnostic inputs

- The GUI passes a bounded PATH snapshot to the Worker through the scan protocol. The snapshot is used for discovery. The Worker and tool processes receive separate allowlisted environments. Raw PATH and tool output are excluded from diagnostic messages.
- Directory and executable checks require a verified local fixed volume before querying path metadata. UNC paths, mapped drives, SUBST drives, removable volumes, and reparse points are excluded.
- Python, Git, and Node.js version checks use fixed arguments and absolute paths that pass the executable trust checks. Processes are started with `shell=False`, explicit environments, a five-second timeout, and bounded stdout and stderr retention. The application requests termination on timeouts and output overflow and bounds cleanup waits.
- npm and Codex CLI are discovery-only. The Codex configuration audit inspects metadata at the default current-user `.codex\config.toml` location. Configuration contents, authentication files and caches, credentials, browser data, and account state are outside the scan.

## Display and export

- The GUI and report renderers use shared redaction rules for known secret patterns, machine names, and personal paths. Output uses an explicit field allowlist and fixed error summaries. Rule-based redaction has limited coverage of arbitrary secrets.
- HTML renders diagnostic text with escaping and uses fixed local styling. The renderer excludes scripts and remote resources.
- JSON and HTML file export remains disabled by default. The GUI, handlers, and file writer enforce the privacy gate independently. The writer serializes final replacement with approval revocation and checks permission again before committing the file.

## Security evidence

Executable trust checks provide a local path and writability safeguard. Full Windows ACL proof remains incomplete, and replacement between a path check and launch remains a separate unresolved risk. The Worker lifecycle uses a Windows Job and supervised IPC. The advanced independent trust-root work remains outside the 0.1.0 release scope.
