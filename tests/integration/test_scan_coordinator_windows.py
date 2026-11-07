import os

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "nt" or os.environ.get("DEVENV_DOCTOR_RUN_WINDOWS_INTEGRATION") != "1",
    reason="Explicit Windows coordinator integration opt-in is not enabled",
)


def test_windows_coordinator_integration_requires_explicit_stage_fixture():
    """Exercise only the fixed protocol worker and native resource lifecycle."""
    from dev_env_doctor.core.scan_control import ScanDeadline
    from dev_env_doctor.core.scan_coordinator import ScanCoordinator
    from dev_env_doctor.core.scan_supervisor import EvidenceStatus

    coordinator = ScanCoordinator("d" * 32, ScanDeadline(10.0))
    try:
        started = coordinator.start(remaining_timeout_ms=2000)
        assert started.facts.worker_started is EvidenceStatus.CONFIRMED
        assert coordinator.child_copies_confirmed
        ready = coordinator.wait_ready()
        assert ready.facts.ready and ready.start_permitted
        running = coordinator.send_start()
        assert running.facts.start_authorized
        candidate = coordinator.receive_worker_message()
        assert candidate.facts.candidate_count == 1
        assert candidate.facts.report_validation is EvidenceStatus.CONFIRMED
        assert coordinator.candidate_diagnostics is not None
        candidate_report = coordinator.candidate_report
        assert candidate_report is not None
        assert set(candidate_report) == {"schema_version", "metadata", "diagnostics"}
        assert set(candidate_report["metadata"]) == {
            "scan_time",
            "app_version",
            "platform",
            "python_version",
        }

        exited = coordinator.observe_process(3000)
        assert exited.facts.resources.worker_exited is EvidenceStatus.CONFIRMED
        assert exited.facts.resources.exit_code == 0
        job = coordinator.observe_job()
        assert job.facts.resources.job_observed is EvidenceStatus.CONFIRMED
        assert job.facts.resources.job_active_processes == 0
        ipc = coordinator.close_ipc()
        assert ipc.facts.resources.ipc_closed is EvidenceStatus.CONFIRMED
        assert ipc.facts.resources.threads_finished is EvidenceStatus.CONFIRMED
        final = coordinator.close_resources()
        assert final.result_available is True
        assert coordinator.supervisor.result is not None
        assert coordinator.result_report == candidate_report
        assert final.facts.resources.parent_resources_closed is EvidenceStatus.CONFIRMED
        assert coordinator.state.value == "closed"
    finally:
        try:
            coordinator.close_resources()
        except BaseException:
            pass
