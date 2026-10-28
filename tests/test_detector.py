import unittest
from datetime import datetime, timezone, timedelta
from ids.detector import DetectionEngine


class DetectorTests(unittest.TestCase):
    def event(self, n, ip="192.168.1.50", timestamp=None):
        timestamp = timestamp or (datetime.now(timezone.utc) + timedelta(seconds=n)).isoformat()
        return {"timestamp": timestamp, "remote_ip": ip, "remote_port": 443,
                "key": f"local:50{n}->{ip}:443"}

    def test_below_threshold_no_alert(self):
        engine = DetectionEngine(threshold=4, window_seconds=60)
        for n in range(3):
            self.assertIsNone(engine.analyze(self.event(n)))

    def test_threshold_triggers_alert(self):
        engine = DetectionEngine(threshold=3, window_seconds=60)
        results = [engine.analyze(self.event(n)) for n in range(3)]
        self.assertIsNotNone(results[-1])
        self.assertEqual(results[-1]["type"], "connection_burst_heuristic")

    def test_duplicate_connection_not_counted_twice(self):
        engine = DetectionEngine(threshold=2, window_seconds=60)
        event = self.event(1)
        self.assertIsNone(engine.analyze(event))
        self.assertIsNone(engine.analyze(event))


if __name__ == "__main__":
    unittest.main()
