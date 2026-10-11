"""Tests for the CyberGuard log analyzer."""
import tempfile
import unittest
from pathlib import Path

from log_analyzer import count_events, find_suspicious_ips, read_log_file


SAMPLE_ENTRIES = [
    "2026-10-11 09:10:01 FAILED_LOGIN ip=192.168.1.20 user=admin",
    "2026-10-11 09:10:05 FAILED_LOGIN ip=192.168.1.20 user=admin",
    "2026-10-11 09:10:08 FAILED_LOGIN ip=192.168.1.20 user=root",
    "2026-10-11 09:10:12 FAILED_LOGIN ip=192.168.1.20 user=admin",
    "2026-10-11 09:11:20 SUCCESS_LOGIN ip=192.168.1.15 user=azhar",
    "2026-10-11 09:12:03 FAILED_LOGIN ip=192.168.1.35 user=test",
    "2026-10-11 09:12:10 SUCCESS_LOGIN ip=192.168.1.35 user=test",
    "2026-10-11 09:13:44 FAILED_LOGIN ip=10.0.0.8 user=guest",
    "2026-10-11 09:13:50 FAILED_LOGIN ip=10.0.0.8 user=guest",
    "2026-10-11 09:14:02 FAILED_LOGIN ip=10.0.0.8 user=guest",
    "2026-10-11 09:14:15 FAILED_LOGIN ip=10.0.0.8 user=guest",
    "2026-10-11 09:14:20 FAILED_LOGIN ip=10.0.0.8 user=guest",
]


class LogAnalyzerTests(unittest.TestCase):
    def test_read_log_file_skips_blank_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "auth.log"
            log_path.write_text("first event\n\nsecond event\n", encoding="utf-8")

            self.assertEqual(
                read_log_file(str(log_path)),
                ["first event", "second event"],
            )

    def test_count_events(self):
        self.assertEqual(
            count_events(SAMPLE_ENTRIES),
            {
                "failed_logins": 10,
                "successful_logins": 2,
                "unrecognized_events": 0,
            },
        )

    def test_find_suspicious_ips(self):
        self.assertEqual(
            find_suspicious_ips(SAMPLE_ENTRIES),
            {"10.0.0.8": 5, "192.168.1.20": 4},
        )

    def test_custom_threshold(self):
        self.assertEqual(
            find_suspicious_ips(SAMPLE_ENTRIES, threshold=5),
            {"10.0.0.8": 5},
        )

    def test_threshold_must_be_positive(self):
        with self.assertRaises(ValueError):
            find_suspicious_ips(SAMPLE_ENTRIES, threshold=0)

    def test_invalid_ip_is_ignored(self):
        entries = [
            "2026-10-11 09:10:01 FAILED_LOGIN ip=not-an-ip user=admin",
        ]
        self.assertEqual(find_suspicious_ips(entries, threshold=1), {})

    def test_unknown_event_is_counted(self):
        entries = ["2026-10-11 09:10:01 UNKNOWN_EVENT ip=192.168.1.1"]
        self.assertEqual(
            count_events(entries),
            {
                "failed_logins": 0,
                "successful_logins": 0,
                "unrecognized_events": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()
