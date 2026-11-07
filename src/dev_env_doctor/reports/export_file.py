"""Privacy approval and atomic JSON/HTML report file writes."""

from contextlib import suppress
from threading import Lock

from PySide6.QtCore import QIODevice, QSaveFile

_REPORT_EXPORT_APPROVED = False
_APPROVAL_LOCK = Lock()


def report_export_allowed() -> bool:
    """Keep file export closed until a separate privacy review grants approval."""
    return _REPORT_EXPORT_APPROVED is True


def revoke_report_export() -> None:
    """Close approval, ordered against the start of any atomic commit."""
    global _REPORT_EXPORT_APPROVED
    with _APPROVAL_LOCK:
        _REPORT_EXPORT_APPROVED = False


def write_report_file(file_path: str, payload: bytes) -> None:
    """Write a rendered report only after approval, using an atomic save."""
    if not report_export_allowed():
        raise PermissionError("Report export has not been approved.")

    save_file: QSaveFile | None = None
    revoked = False
    try:
        save_file = QSaveFile(file_path)
        save_file.setDirectWriteFallback(False)
        if not save_file.open(QIODevice.OpenModeFlag.WriteOnly):
            raise OSError
        if save_file.write(payload) != len(payload):
            raise OSError
        with _APPROVAL_LOCK:
            # Revocation before this check wins. Once commit begins, it wins.
            revoked = not report_export_allowed()
            if not revoked and save_file.commit():
                return
    except Exception:
        pass
    if save_file is not None:
        with suppress(Exception):
            save_file.cancelWriting()
    if revoked:
        raise PermissionError("Report export has not been approved.") from None
    raise OSError("Could not save the report.") from None
