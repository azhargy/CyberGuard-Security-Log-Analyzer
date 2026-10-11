"""Functions for analyzing authentication logs."""
import ipaddress
from collections import Counter
from pathlib import Path


def read_log_file(file_path: str) -> list[str]:
    """Read a log file and return its non-empty lines."""
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as log_file:
        return [line.strip() for line in log_file if line.strip()]


def count_events(log_entries: list[str]) -> dict[str, int]:
    """Count failed, successful, and unrecognized login events."""
    counts = Counter()

    for entry in log_entries:
        fields = entry.split()

        if len(fields) < 3:
            counts["unrecognized_events"] += 1
        elif fields[2] == "FAILED_LOGIN":
            counts["failed_logins"] += 1
        elif fields[2] == "SUCCESS_LOGIN":
            counts["successful_logins"] += 1
        else:
            counts["unrecognized_events"] += 1

    return {
        "failed_logins": counts["failed_logins"],
        "successful_logins": counts["successful_logins"],
        "unrecognized_events": counts["unrecognized_events"],
    }


def find_suspicious_ips(
    log_entries: list[str],
    threshold: int = 4,
) -> dict[str, int]:
    """Find IP addresses with failed attempts at or above the threshold."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    failed_attempts: Counter[str] = Counter()

    for entry in log_entries:
        fields = entry.split()

        if len(fields) < 3 or fields[2] != "FAILED_LOGIN":
            continue

        ip_field = next(
            (field for field in fields if field.startswith("ip=")),
            None,
        )

        if ip_field is None:
            continue

        ip = ip_field.removeprefix("ip=")

        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue

        failed_attempts[ip] += 1

    return {
        ip: attempts
        for ip, attempts in sorted(failed_attempts.items())
        if attempts >= threshold
    }
