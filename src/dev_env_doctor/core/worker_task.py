from enum import StrEnum


class WorkerTaskMode(StrEnum):
    FULL_SCAN = "full_scan"
    ENVIRONMENT_PROBE = "environment_probe"
