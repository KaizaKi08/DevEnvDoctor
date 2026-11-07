import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "nt" or os.environ.get("DEVENV_DOCTOR_RUN_WINDOWS_INTEGRATION") != "1",
    reason="Explicit Windows worker integration opt-in is not enabled",
)


def test_windows_worker_runs_one_scan_and_sends_candidate():
    from dev_env_doctor.core.scan_ipc import FramedTransport, PipePair
    from dev_env_doctor.core.scan_worker import WorkerSession, WorkerState
    from dev_env_doctor.core.windows_job import WindowsJob

    session_id = "e" * 32
    pair = PipePair.create()
    worker = WorkerSession(
        job=WindowsJob(),
        transport=FramedTransport(pair.parent),
        child_handles=pair.child_handles,
        close_child_copies=pair.close_child_copies,
        session_id=session_id,
    )
    try:
        worker.start(
            (
                sys.executable,
                "-m",
                "dev_env_doctor.core.scan_worker_entry",
                "--session",
                session_id,
                "--read-handle",
                str(pair.child_handles[0]),
                "--write-handle",
                str(pair.child_handles[1]),
            ),
            remaining_timeout_ms=5000,
        )
        worker.wait_ready()
        worker.send_start(10**6)
        candidate = worker.receive_child_message()
        assert candidate["type"] == "RESULT_CANDIDATE"
        report = candidate["payload"]["report"]
        assert set(report) == {"schema_version", "metadata", "diagnostics"}
        assert report["schema_version"] == "1.0"
        assert set(report["metadata"]) == {
            "scan_time",
            "app_version",
            "platform",
            "python_version",
        }
        assert isinstance(report["diagnostics"], list)
        assert worker.wait_process(10000).exit_code == 0
        worker.observe_job_empty()
        worker.close()
        assert worker.state is WorkerState.CLOSED
    finally:
        pair.parent.close()
