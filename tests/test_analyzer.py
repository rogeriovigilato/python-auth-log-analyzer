import csv
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from analyzer import (
    find_suspicious_window,
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


def make_failure(user="admin", ip="192.0.2.10"):
    return {
        "timestamp": datetime(2026, 10, 9, 14, 0, 0),
        "status": "Failed",
        "user": user,
        "ip": ip,
    }


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


if __name__ == "__main__":
    unittest.main()
