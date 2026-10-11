"""Command-line interface for CyberGuard."""
import argparse
import csv
from pathlib import Path

from log_analyzer import count_events, find_suspicious_ips, read_log_file


def write_report(suspicious_ips: dict[str, int], output_path: Path) -> None:
    """Write suspicious IP addresses to a CSV report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.writer(report_file)
        writer.writerow(["ip_address", "failed_attempts", "status"])

        for ip, attempts in suspicious_ips.items():
            writer.writerow([ip, attempts, "FLAGGED"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for repeated failed logins."
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("sample_logs/auth.log"),
        help="Path to the authentication log file.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=4,
        help="Minimum failed attempts needed to flag an IP (default: 4).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/suspicious_ips.csv"),
        help="Path for the CSV report.",
    )
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1.")

    try:
        entries = read_log_file(str(args.log))
    except (OSError, UnicodeError) as error:
        parser.error(f"could not read log file: {error}")

    event_counts = count_events(entries)
    suspicious_ips = find_suspicious_ips(entries, args.threshold)

    print("CyberGuard Security Log Analyzer")
    print("-" * 34)
    print(f"Log entries analyzed: {len(entries)}")
    print(f"Failed logins: {event_counts['failed_logins']}")
    print(f"Successful logins: {event_counts['successful_logins']}")
    print(f"Unrecognized events: {event_counts['unrecognized_events']}")
    print(f"Detection threshold: {args.threshold}")

    if suspicious_ips:
        print("\nSuspicious IP addresses:")
        for ip, attempts in suspicious_ips.items():
            print(f"  {ip}: {attempts} failed attempts")
    else:
        print("\nNo IP addresses met the detection threshold.")

    try:
        write_report(suspicious_ips, args.output)
    except OSError as error:
        parser.error(f"could not write report: {error}")

    print(f"\nCSV report saved to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
