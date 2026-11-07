import base64
import html
import json
import traceback
from datetime import UTC, datetime
from urllib.parse import quote, quote_plus

import pytest

from dev_env_doctor.core.models import DiagnosticResult, ScanMetadata, ScanReport, Severity
from dev_env_doctor.core.scan_protocol import MessageType, decode_frame
from dev_env_doctor.core.scan_worker_entry import _candidate_payload, _message
from dev_env_doctor.core.supervised_scan import _report_from_verified_payload
from dev_env_doctor.privacy.redaction import redact_text
from dev_env_doctor.reports import html_report, json_report


def _report(summary: str, *, rule: str = "COMMAND_TIMEOUT") -> ScanReport:
    return ScanReport(
        metadata=ScanMetadata(
            scan_time=datetime(2020, 1, 1, tzinfo=UTC),
            platform="PHASE12-METADATA-CANARY-3641",
        ),
        diagnostics=[
            DiagnosticResult(
                rule_id=rule,
                title="Synthetic tool check",
                severity=Severity.ERROR,
                summary=summary,
                suggestion="Review locally.",
                evidence=["PHASE12-EVIDENCE-CANARY-1351"],
                status="error",
            )
        ],
    )


def _through_candidate(report: ScanReport) -> ScanReport:
    frame = _message(
        "a" * 32, 2, MessageType.RESULT_CANDIDATE, {"report": _candidate_payload(report)}
    )
    return _report_from_verified_payload(decode_frame(frame)["payload"]["report"])


@pytest.fixture(params=["json", "html"])
def renderer(request):
    if request.param == "json":
        return json_report, json_report.render_json_report, json_report.JSONReportError
    return html_report, html_report.render_html_report, html_report.HTMLReportError


@pytest.mark.parametrize(
    "encode",
    [
        pytest.param(lambda value: quote(value, safe=""), id="percent"),
        pytest.param(lambda value: quote_plus(value), id="form-percent"),
        pytest.param(lambda value: "".join(f"&#{ord(c)};" for c in value), id="html"),
        pytest.param(lambda value: json.dumps(value, ensure_ascii=True), id="json-string"),
        pytest.param(lambda value: "".join(f"\\u{ord(c):04x}" for c in value), id="unicode"),
        pytest.param(lambda value: base64.b64encode(value.encode()).decode(), id="base64"),
        pytest.param(
            lambda value: quote(base64.urlsafe_b64encode(value.encode()).decode(), safe=""),
            id="percent-base64",
        ),
    ],
)
@pytest.mark.parametrize(
    "raw",
    [
        'Authorization: "PHASE12-SECRET-9241-\u96ea"',
        r"Path \\?\UNC\PHASE12-SERVER-9241\share\tool.exe",
    ],
    ids=["credential", "path"],
)
def test_encoded_sensitive_input_is_removed_before_output(renderer, encode, raw: str) -> None:
    _, render, _ = renderer
    encoded = encode(raw)
    output = render(_through_candidate(_report(f"Tool emitted {encoded}")))
    assert "9241" not in output
    assert encoded not in html.unescape(output)
    assert ("<REDACTED>" in output) or ("&lt;REDACTED&gt;" in output)


@pytest.mark.parametrize(
    ("value", "private_fragment"),
    [
        (r'File "C:\Users\PHASE12-USER-1731\notes.txt".', "USER-1731"),
        (r'File "D:\Profiles\PHASE12-PROFILE-1731\notes.txt".', "PROFILE-1731"),
        (r'File "\\PHASE12-SERVER-1731\share\notes.txt".', "SERVER-1731"),
        (r'File "\\?\UNC\PHASE12-EXTUNC-1731\share\notes.txt".', "EXTUNC-1731"),
        (r"Device \\.\PHASE12-DEVICE-1731\pipe", "DEVICE-1731"),
        (r"Device \Device\HarddiskVolume1\PHASE12-NATIVE-1731\file", "NATIVE-1731"),
        (
            "Directory C:\\Users\\Lab\\Private PHASE12-FOLDER-1731\nNext line\nLast line",
            "FOLDER-1731",
        ),
        ("Directory C:\\Users\\ \n  PHASE12-SPLIT-1731\\work", "SPLIT-1731"),
        ("Directory \\ \n \\PHASE12-UNCWRAP-1731\\share\\work", "UNCWRAP-1731"),
        ("Directory C:\\Users\\PHASE12-\n  PARTIAL-1731\\work", "PARTIAL-1731"),
        (r"Directory C : \Users\PHASE12-DRIVESPLIT-1731\work", "DRIVESPLIT-1731"),
        (r"Directory \\server \PHASE12-SHARESPLIT-1731\work", "SHARESPLIT-1731"),
        ("Directory C:\\Users\\PHASE12-\nUNINDENTED-1731\\work", "UNINDENTED-1731"),
    ],
)
def test_windows_path_variants_do_not_survive_candidate_round_trip(
    renderer, value: str, private_fragment: str
) -> None:
    _, render, _ = renderer
    output = render(_through_candidate(_report(value)))
    assert private_fragment not in output
    if "Next line" in value:
        assert "Next line" in output and "Last line" in output
    assert "Review locally." in output


def test_exception_text_and_report_metadata_do_not_survive(renderer) -> None:
    _, render, _ = renderer
    report = _report("Unlabelled PHASE12-EXCEPTION-CANARY-63AE", rule="COMMAND_PROBE_EXCEPTION")
    report.diagnostics[0].title = "PHASE12-TITLE-CANARY-63AE"
    report.diagnostics[0].suggestion = "PHASE12-SUGGESTION-CANARY-63AE"
    output = render(_through_candidate(report))
    assert "COMMAND_PROBE_EXCEPTION" in output
    assert all(
        label not in output
        for label in ("63AE", "PHASE12-METADATA-CANARY", "PHASE12-EVIDENCE-CANARY")
    )


def test_renderer_drops_underlying_exception_chain(renderer, monkeypatch) -> None:
    module, render, safe_error = renderer

    def fail(*args, **kwargs):
        try:
            raise ValueError("PHASE12-CONTEXT-CANARY-7751")
        except ValueError as error:
            raise RuntimeError("PHASE12-CAUSE-CANARY-7751") from error

    monkeypatch.setattr(module, "build_json_payload", fail)
    with pytest.raises(safe_error) as captured:
        render(_report("Safe diagnostic."))
    error = captured.value
    assert error.__cause__ is None and error.__context__ is None
    assert "7751" not in repr(error)
    assert "7751" not in "".join(traceback.format_exception(error))


def test_nested_encoding_is_bounded_and_ordinary_diagnostics_remain_intact() -> None:
    value = "Token=PHASE12-RECURSION-CANARY-4314"
    for _ in range(8):
        value = quote(value, safe="")
    assert redact_text(value) == "<REDACTED>"
    benign = "Version%20check finished. Label YWJjZGVm remains unchanged."
    assert redact_text(benign) == benign


@pytest.mark.parametrize(
    "summary",
    [
        r"Unexpected \"Authorization\"\u003a\u0020\"PHASE12-FRAGMENT-20E1\"",
        r"Unexpected \\\\?\\UNC\\PHASE12-FRAGMENT-20E1\\share\\notes.txt",
    ],
)
def test_unquoted_json_escaped_fragments_are_redacted(renderer, summary: str) -> None:
    _, render, _ = renderer
    assert "20E1" not in render(_through_candidate(_report(summary)))


@pytest.mark.parametrize(
    "summary",
    [
        "RuntimeError: PHASE12-EXCEPTION-7CA1",
        "ValueError('PHASE12-EXCEPTION-7CA1')",
        "Traceback (most recent call last):\nsynthetic PHASE12-EXCEPTION-7CA1",
    ],
)
def test_exception_text_in_other_reviewed_diagnostics_is_redacted(renderer, summary: str) -> None:
    _, render, _ = renderer
    assert "7CA1" not in render(_through_candidate(_report(summary)))
