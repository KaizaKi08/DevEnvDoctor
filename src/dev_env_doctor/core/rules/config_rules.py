"""Fixed, privacy-reviewed text for Codex configuration outcomes."""

from typing import Literal, NamedTuple

from dev_env_doctor.collectors.config_files import CodexConfigState
from dev_env_doctor.core.models import DiagnosticResult, Severity


class ConfigFinding(NamedTuple):
    title: str
    summary: str
    suggestion: str
    severity: Severity
    status: Literal["found", "passed", "skipped", "error"]


CODEX_CONFIG_FINDINGS = {
    CodexConfigState.PRESENT.value: ConfigFinding(
        "Codex 配置文件存在",
        "已确认 config.toml 为本地普通文件，已检查的路径未发现重解析点。核验范围仅限路径和元数据。",
        "如需检查设置，请在 Codex 的本地配置界面查看用户配置。",
        Severity.INFO,
        "passed",
    ),
    CodexConfigState.MISSING.value: ConfigFinding(
        "Codex 配置文件缺失",
        "默认位置未找到 config.toml，已检查的父路径未发现重解析点。",
        "默认设置可在没有用户配置时使用。如需自定义，请从 Codex 的配置入口保存用户设置。",
        Severity.INFO,
        "found",
    ),
    CodexConfigState.INACCESSIBLE.value: ConfigFinding(
        "Codex 配置不可访问",
        "配置路径的元数据访问被拒绝或受锁限制。文件存在性和路径安全性无法确认。",
        "检查默认配置目录的当前用户访问权限，或关闭占用该文件的程序后重试。",
        Severity.WARNING,
        "skipped",
    ),
    CodexConfigState.UNSAFE.value: ConfigFinding(
        "Codex 配置路径未通过安全检查",
        "路径未通过本地固定卷或路径属性检查。配置文件无法安全核验。",
        "确认默认配置使用本地固定卷和普通目录，并检查目录链接或同步占位文件。",
        Severity.WARNING,
        "skipped",
    ),
    CodexConfigState.INVALID_FILE.value: ConfigFinding(
        "Codex 配置文件类型异常",
        "默认位置存在同名项，但其元数据不符合普通文件要求。",
        "核对默认位置是否有同名目录或设备条目。保留原数据并在 Codex 中确认配置位置。",
        Severity.WARNING,
        "found",
    ),
    CodexConfigState.TOO_LARGE.value: ConfigFinding(
        "Codex 配置文件超过审计上限",
        "默认配置为本地普通文件，但大小超过 1 MiB，元数据审计未通过。",
        "在本地确认文件是否为预期的 Codex 用户配置。保留备份，再通过 Codex 核对配置。",
        Severity.WARNING,
        "found",
    ),
    CodexConfigState.UNVERIFIED.value: ConfigFinding(
        "Codex 配置无法验证",
        "未能确认当前用户配置目录或读取所需元数据，文件存在性未知。",
        "确认当前 Windows 用户的本地配置目录可用，再重试扫描。",
        Severity.INFO,
        "skipped",
    ),
}
_CODEX_CLI_TEXT = {
    True: "Codex CLI：已发现，仅查找。",
    False: "Codex CLI：在允许的位置未发现。",
    None: "Codex CLI：查找结果无法确认。",
}
CODEX_CLI_EVIDENCE = frozenset(_CODEX_CLI_TEXT.values())


def codex_config_diagnostic(state: CodexConfigState, *, cli_found: bool | None) -> DiagnosticResult:
    finding = CODEX_CONFIG_FINDINGS[state.value]
    return DiagnosticResult(
        rule_id=state.value,
        title=finding.title,
        summary=finding.summary,
        suggestion=finding.suggestion,
        severity=finding.severity,
        status=finding.status,
        evidence=[_CODEX_CLI_TEXT[cli_found]],
    )
