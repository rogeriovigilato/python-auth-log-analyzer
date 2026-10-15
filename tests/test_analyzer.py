import unittest
from datetime import datetime, timedelta

from analyzer import find_suspicious_window


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


if __name__ == "__main__":
    unittest.main()
