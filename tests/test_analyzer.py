import csv
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from analyzer import (
    AlertTracker,
    FailureCsvWriter,
    find_suspicious_window,
    match_line,
    parse_line,
    write_failures_csv,
)


def make_events(minutes):
    start = datetime(2026, 10, 9, 14, 0, 0)

    return [
        {
            "timestamp": start + timedelta(minutes=minute),
            "status": "Failed",
            "user": "admin",
            "ip": "192.0.2.10",
        }
        for minute in minutes
    ]


def make_failure(user="admin", ip="192.0.2.10", minute=0):
    return {
        "timestamp": datetime(2026, 10, 9, 14, 0, 0)
        + timedelta(minutes=minute),
        "status": "Failed",
        "user": user,
        "ip": ip,
    }


ISO_VM_LINE = (
    "2026-10-14T20:00:12.183014-03:00 host sshd[2421]: "
    "Failed password for invalid user admin "
    "from 203.0.113.77 port 51201 ssh2"
)


class TestSuspiciousWindow(unittest.TestCase):
    def test_five_failures_inside_window(self):
        events = make_events([0, 1, 2, 3, 4])

        result = find_suspicious_window(
            events, threshold=5, window_minutes=10
        )

        self.assertEqual(len(result), 5)

    def test_spread_out_failures_do_not_alert(self):
        events = make_events([0, 11, 22, 33, 44])

        result = find_suspicious_window(
            events, threshold=5, window_minutes=10
        )

        self.assertEqual(result, [])

    def test_four_failures_do_not_alert(self):
        events = make_events([0, 1, 2, 3])

        result = find_suspicious_window(
            events, threshold=5, window_minutes=10
        )

        self.assertEqual(result, [])

    def test_exactly_ten_minutes_alerts(self):
        events = make_events([0, 2, 4, 6, 10])

        result = find_suspicious_window(
            events, threshold=5, window_minutes=10
        )

        self.assertEqual(len(result), 5)
        self.assertEqual(
            result[-1]["timestamp"] - result[0]["timestamp"],
            timedelta(minutes=10),
        )

    def test_unordered_events_are_sorted(self):
        events = make_events([4, 0, 3, 1, 2])

        result = find_suspicious_window(
            events, threshold=5, window_minutes=10
        )

        self.assertEqual(len(result), 5)
        self.assertEqual(
            [event["timestamp"] for event in result],
            sorted(event["timestamp"] for event in events),
        )

    def test_window_moves_past_old_event(self):
        events = make_events([0, 20, 21, 22, 23, 24])

        result = find_suspicious_window(
            events, threshold=5, window_minutes=10
        )

        self.assertEqual(len(result), 5)
        self.assertEqual(result[0]["timestamp"], events[1]["timestamp"])
        self.assertEqual(result[-1]["timestamp"], events[-1]["timestamp"])

    def test_empty_events_do_not_alert(self):
        result = find_suspicious_window(
            [], threshold=5, window_minutes=10
        )

        self.assertEqual(result, [])


class TestParseLine(unittest.TestCase):
    def test_valid_line_is_parsed(self):
        line = (
            "2026-10-09T14:00:00 lab-linux sshd[1201]: "
            "Failed password for invalid user admin "
            "from 192.0.2.10 port 51001 ssh2"
        )

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["status"], "Failed")
        self.assertEqual(event["user"], "admin")
        self.assertEqual(event["ip"], "192.0.2.10")
        self.assertEqual(
            event["timestamp"],
            datetime(2026, 10, 9, 14, 0, 0),
        )

    def test_invalid_date_returns_none(self):
        line = (
            "2026-13-40T99:99:99 lab-linux sshd[1201]: "
            "Failed password for admin "
            "from 192.0.2.10 port 51001 ssh2"
        )

        self.assertIsNone(parse_line(line))

    def test_invalid_ip_returns_none(self):
        line = (
            "2026-10-09T14:00:00 lab-linux sshd[1201]: "
            "Failed password for admin "
            "from not-an-ip port 51001 ssh2"
        )

        self.assertIsNone(parse_line(line))

    def test_unrecognized_line_returns_none(self):
        self.assertIsNone(parse_line("linha invalida"))

    def test_control_characters_are_escaped(self):
        line = (
            "2026-10-09T14:00:00 lab-linux sshd[1201]: "
            "Failed password for \x1b[31mroot "
            "from 192.0.2.10 port 51001 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["user"], "\\x1b[31mroot")


class TestFormats(unittest.TestCase):
    def test_iso_with_microseconds_and_offset(self):
        event = parse_line(ISO_VM_LINE)

        self.assertIsNotNone(event)
        self.assertEqual(
            event["timestamp"],
            datetime(2026, 10, 14, 20, 0, 12, 183014),
        )
        self.assertEqual(event["ip"], "203.0.113.77")

    def test_iso_offset_without_colon(self):
        line = (
            "2026-10-14T20:00:12+0000 host sshd[2421]: "
            "Failed password for admin from 203.0.113.77 "
            "port 51201 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(
            event["timestamp"],
            datetime(2026, 10, 14, 20, 0, 12),
        )

    def test_classic_syslog_uses_reference_year(self):
        line = (
            "Oct  9 14:00:00 lab-linux sshd[1201]: "
            "Failed password for admin from 192.0.2.10 "
            "port 51001 ssh2"
        )

        event = parse_line(line, reference=datetime(2026, 10, 16))

        self.assertEqual(
            event["timestamp"],
            datetime(2026, 10, 9, 14, 0, 0),
        )

    def test_classic_syslog_rolls_back_over_new_year(self):
        line = (
            "Dec 31 23:59:00 lab-linux sshd[1201]: "
            "Failed password for admin from 192.0.2.10 "
            "port 51001 ssh2"
        )

        event = parse_line(line, reference=datetime(2026, 1, 2))

        self.assertEqual(
            event["timestamp"],
            datetime(2025, 12, 31, 23, 59, 0),
        )

    def test_publickey_failure_is_parsed(self):
        line = (
            "2026-10-14T20:00:12+00:00 host sshd[2421]: "
            "Failed publickey for postgres from 203.0.113.77 "
            "port 51201 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["status"], "Failed")
        self.assertEqual(event["user"], "postgres")

    def test_match_line_reports_the_format_name(self):
        name, event = match_line(ISO_VM_LINE)

        self.assertEqual(name, "iso")
        self.assertIsNotNone(event)

        name, event = match_line(
            "Oct  9 14:00:00 lab-linux sshd[1201]: "
            "Failed password for admin from 192.0.2.10 "
            "port 51001 ssh2",
            reference=datetime(2026, 10, 16),
        )

        self.assertEqual(name, "syslog")

        self.assertEqual(match_line("linha invalida"), (None, None))


class TestAlertTracker(unittest.TestCase):
    def test_threshold_inside_window_alerts(self):
        tracker = AlertTracker(threshold=5, window_minutes=10)

        results = [
            tracker.add_failure(make_failure(minute=minute))
            for minute in range(5)
        ]

        self.assertIsNone(results[3])
        self.assertEqual(len(results[4]), 5)

    def test_repeats_alert_only_after_window_rolls(self):
        tracker = AlertTracker(threshold=2, window_minutes=10)

        self.assertIsNone(tracker.add_failure(make_failure(minute=0)))
        self.assertIsNotNone(
            tracker.add_failure(make_failure(minute=1))
        )
        self.assertIsNone(tracker.add_failure(make_failure(minute=2)))
        self.assertIsNone(tracker.add_failure(make_failure(minute=21)))
        self.assertIsNotNone(
            tracker.add_failure(make_failure(minute=22))
        )

    def test_pruning_keeps_memory_bounded(self):
        tracker = AlertTracker(threshold=5, window_minutes=10)

        for minute in range(0, 120, 3):
            tracker.add_failure(make_failure(minute=minute))

        stored = tracker.events_by_ip["192.0.2.10"]

        self.assertLessEqual(len(stored), 4)


class TestCsvExport(unittest.TestCase):
    def export_single_failure(self, user):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "result.csv"
            write_failures_csv([make_failure(user=user)], output_path)

            with output_path.open(
                encoding="utf-8",
                newline="",
            ) as csv_file:
                return list(csv.DictReader(csv_file))

    def test_formula_prefixes_are_neutralized(self):
        for prefix in ("=", "+", "-", "@"):
            with self.subTest(prefix=prefix):
                rows = self.export_single_failure(prefix + "1+1")

                self.assertEqual(
                    rows[0]["user"], "'" + prefix + "1+1"
                )

    def test_control_characters_are_escaped(self):
        rows = self.export_single_failure("\x1b[31mroot")

        self.assertEqual(rows[0]["user"], "\\x1b[31mroot")

    def test_normal_values_are_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "result.csv"
            write_failures_csv([make_failure()], output_path)

            with output_path.open(
                encoding="utf-8",
                newline="",
            ) as csv_file:
                rows = list(csv.DictReader(csv_file))

        self.assertEqual(rows[0]["user"], "admin")
        self.assertEqual(rows[0]["ip"], "192.0.2.10")
        self.assertEqual(rows[0]["status"], "Failed")


class TestFailureCsvWriter(unittest.TestCase):
    def test_writes_rows_incrementally(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "result.csv"
            writer = FailureCsvWriter(output_path)

            writer.write(make_failure(user="=2+2"))
            writer.write(make_failure(user="admin"))
            writer.close()

            with output_path.open(
                encoding="utf-8",
                newline="",
            ) as csv_file:
                rows = list(csv.DictReader(csv_file))

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["user"], "'=2+2")
        self.assertEqual(rows[1]["user"], "admin")


if __name__ == "__main__":
    unittest.main()
