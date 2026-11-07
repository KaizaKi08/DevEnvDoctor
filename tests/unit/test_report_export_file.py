import base64
import html
import json
from pathlib import Path
from threading import Event, Lock, Thread
from unittest.mock import Mock
from urllib.parse import quote

import pytest

from dev_env_doctor.core.models import DiagnosticResult, ScanReport, Severity
from dev_env_doctor.reports import export_file
from dev_env_doctor.reports.html_report import render_html_report
from dev_env_doctor.reports.json_report import render_json_report


@pytest.mark.parametrize("extension", ["json", "html"])
def test_direct_writer_denies_creation_and_overwrite(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, extension: str
) -> None:
    save_file = Mock()
    monkeypatch.setattr(export_file, "QSaveFile", save_file)
    destination = tmp_path / f"report.{extension}"

    with pytest.raises(PermissionError, match="Report export has not been approved."):
        export_file.write_report_file(str(destination), b"synthetic report")
    assert list(tmp_path.iterdir()) == []

    destination.write_bytes(b"keep-existing-report")
    with pytest.raises(PermissionError, match="Report export has not been approved."):
        export_file.write_report_file(str(destination), b"synthetic report")
    assert destination.read_bytes() == b"keep-existing-report"
    assert list(tmp_path.iterdir()) == [destination]
    save_file.assert_not_called()


@pytest.mark.parametrize(
    ("extension", "render"), [("json", render_json_report), ("html", render_html_report)]
)
def test_synthetic_privacy_in_serialized_and_written_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, extension, render
) -> None:
    secrets = {
        "API Key": 'MVP-P1-api-82c8-密<>&"',
        "Token": 'MVP-P1-token-07e5-密<>&"',
        "Password": 'MVP-P1-password-01ea-密<>&"',
        "Authorization": 'MVP-P1-auth-4c23-密<>&"',
    }
    user_path = r"C:\Users\MVP-P1-User-3d0a\Documents\notes.txt"
    unc_path = r"\\MVP-P1-Server-92ab\share\notes.txt"
    machine = "MVP-P1-HOST-770E"
    config_secret = 'MVP-P1-config-71b9-密<>&"'
    exception_secret = 'MVP-P1-exception-a8de-密<>&"'
    markup = '<script>window.synthetic = "mvp";</script>'
    diagnostic = DiagnosticResult(
        rule_id="COMMAND_TIMEOUT",
        title=markup,
        severity=Severity.WARNING,
        status="error",
        summary=" ".join(f"{key}='{value}'" for key, value in secrets.items()),
        evidence=[f"Raw tool exception: {exception_secret}"],
        suggestion=f'Host {machine}. User path "{user_path}" and network path "{unc_path}".',
    )
    report = ScanReport(diagnostics=[diagnostic])
    object.__setattr__(report, "synthetic_config", {"password": config_secret})

    serialized = render(report, machine_names=(machine,))
    monkeypatch.setattr(export_file, "_REPORT_EXPORT_APPROVED", True)
    destination = tmp_path / f"dev-env-doctor-report.{extension}"
    export_file.write_report_file(str(destination), serialized.encode("utf-8"))
    saved = destination.read_text(encoding="utf-8")
    assert saved == serialized
    if extension == "json":
        parsed = json.loads(saved)["diagnostics"][0]
        assert parsed["title"] == markup
        assert parsed["evidence"] == []
        assert "<MACHINE>" in parsed["suggestion"]
        assert "<USER_DIR>" in parsed["suggestion"]
        assert "<PATH>" in parsed["suggestion"]
        assert "<REDACTED>" in parsed["summary"]
    else:
        assert html.escape(markup) in saved
        assert "<script>" not in saved
        assert "&lt;MACHINE&gt;" in saved
        assert "&lt;USER_DIR&gt;" in saved
        assert "&lt;PATH&gt;" in saved
        assert "&lt;REDACTED&gt;" in saved

    for value in (*secrets.values(), user_path, unc_path, machine, config_secret, exception_secret):
        for representation in (
            value,
            html.escape(value),
            json.dumps(value, ensure_ascii=True)[1:-1],
            json.dumps(value, ensure_ascii=False)[1:-1],
            base64.b64encode(value.encode("utf-8")).decode("ascii"),
            quote(value, safe=""),
        ):
            assert representation not in saved
            assert representation not in destination.name


def test_writer_replaces_raw_exception_with_fixed_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    destination = tmp_path / "report.json"
    canary = "MVP-P1-WRITER-ERROR-e857"
    save_file = Mock(side_effect=RuntimeError(f"{destination} {canary}"))
    monkeypatch.setattr(export_file, "_REPORT_EXPORT_APPROVED", True)
    monkeypatch.setattr(export_file, "QSaveFile", save_file)

    with pytest.raises(OSError, match=r"^Could not save the report\.$") as captured:
        export_file.write_report_file(str(destination), b"synthetic report")
    assert captured.value.__context__ is None
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("existing", [False, True])
def test_revocation_during_write_cancels_atomic_save(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, existing: bool
) -> None:
    destination = tmp_path / "report.json"
    if existing:
        destination.write_bytes(b"original")
    qt_save_file = export_file.QSaveFile
    commits = Mock()

    class RevokingSaveFile(qt_save_file):
        def write(self, data):
            written = super().write(data)
            export_file.revoke_report_export()
            return written

        def commit(self):
            commits()
            return super().commit()

    monkeypatch.setattr(export_file, "QSaveFile", RevokingSaveFile)
    monkeypatch.setattr(export_file, "_REPORT_EXPORT_APPROVED", True)
    with pytest.raises(PermissionError, match="Report export has not been approved."):
        export_file.write_report_file(str(destination), b"synthetic report")
    commits.assert_not_called()
    if existing:
        assert list(tmp_path.iterdir()) == [destination]
        assert destination.read_bytes() == b"original"
    else:
        assert list(tmp_path.iterdir()) == []


def test_commit_already_entered_is_ordered_before_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = Lock()
    attempted = Event()
    revoked = Event()

    class ObservedLock:
        def __enter__(self):
            if lock.locked():
                attempted.set()
            lock.acquire()

        def __exit__(self, *exc):
            lock.release()

    def revoke() -> None:
        export_file.revoke_report_export()
        revoked.set()

    revoker = Thread(target=revoke, daemon=True)

    def commit() -> bool:
        revoker.start()
        return attempted.wait(2) and not revoked.is_set()

    writer = Mock()
    writer.write.return_value = len(b"synthetic")
    writer.commit.side_effect = commit
    monkeypatch.setattr(export_file, "QSaveFile", Mock(return_value=writer))
    monkeypatch.setattr(export_file, "_REPORT_EXPORT_APPROVED", True)
    monkeypatch.setattr(export_file, "_APPROVAL_LOCK", ObservedLock())
    try:
        export_file.write_report_file("unused.json", b"synthetic")
    finally:
        if revoker.ident is not None:
            revoker.join(2)

    assert revoked.is_set()
    assert not export_file.report_export_allowed()
    writer.commit.assert_called_once()
    writer.cancelWriting.assert_not_called()
