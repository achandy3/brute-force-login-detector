from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from detector import detect_brute_force


def make_record(timestamp="2026-11-04T14:00:00+00:00", **changes):
    """Build a fictional record with optional field overrides for a test."""
    record = {
        "timestamp": timestamp,
        "username": "alex",
        "source_ip": "192.0.2.10",
        "success": False,
    }
    record.update(changes)
    return record


class TestBruteForceDetector(unittest.TestCase):
    def test_no_alert_below_threshold(self):
        records = [
            {
                "timestamp": "2026-11-04T14:00:00+00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "success": False,
            },
            {
                "timestamp": "2026-11-04T14:00:20+00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "success": False,
            },
        ]

        result = detect_brute_force(records)

        self.assertEqual(result["total_failures"], 2)
        self.assertEqual(result["alerts"], [])

    def test_alert_at_threshold(self):
        records = [
            {
                "timestamp": "2026-11-04T14:00:00+00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "success": False,
            },
            {
                "timestamp": "2026-11-04T14:00:20+00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "success": False,
            },
            {
                "timestamp": "2026-11-04T14:00:40+00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "success": False,
            },
        ]

        result = detect_brute_force(records)

        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(result["alerts"][0]["count"], 3)
        self.assertEqual(result["alerts"][0]["source_ip"], "192.0.2.10")

    def test_old_failures_expire(self):
        records = [
            {
                "timestamp": "2026-11-04T14:00:00+00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "success": False,
            },
            {
                "timestamp": "2026-11-04T14:00:20+00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "success": False,
            },
            {
                "timestamp": "2026-11-04T14:02:00+00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "success": False,
            },
        ]

        result = detect_brute_force(records)

        self.assertEqual(result["alerts"], [])
        self.assertEqual(len(result["failures_by_ip"]["192.0.2.10"]), 1)


class TestRecordValidation(unittest.TestCase):
    def setUp(self):
        self.record = {
            "timestamp": "2026-11-04T14:00:00+00:00",
            "username": "alex",
            "source_ip": "192.0.2.10",
            "success": False,
        }

    def test_rejects_non_boolean_success(self):
        for value in ("false", 0, 1, None):
            with self.subTest(value=value):
                record = self.record.copy()
                record["success"] = value
                with self.assertRaisesRegex(ValueError, "Record 1: 'success' must be a Boolean"):
                    detect_brute_force([record])

    def test_rejects_missing_required_fields(self):
        for field in ("timestamp", "username", "source_ip", "success"):
            with self.subTest(field=field):
                record = self.record.copy()
                del record[field]
                with self.assertRaisesRegex(ValueError, f"Record 1 is missing '{field}'"):
                    detect_brute_force([record])

    def test_rejects_invalid_structure(self):
        with self.assertRaisesRegex(ValueError, "Login data must be a list"):
            detect_brute_force({})
        with self.assertRaisesRegex(ValueError, "Record 1 must be an object"):
            detect_brute_force([None])

    def test_rejects_invalid_text_fields(self):
        for field in ("timestamp", "username", "source_ip"):
            for value in ("", "   ", None, 42):
                with self.subTest(field=field, value=value):
                    record = self.record.copy()
                    record[field] = value
                    with self.assertRaisesRegex(
                        ValueError, f"Record 1: '{field}' must be a nonempty string"
                    ):
                        detect_brute_force([record])


class TestDetectionRules(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(
            detect_brute_force([]),
            {"total_failures": 0, "failures_by_ip": {}, "alerts": []},
        )

    def test_successes_do_not_count_or_reset_failures(self):
        records = [
            make_record(),
            make_record("2026-11-04T14:00:20+00:00"),
            make_record("2026-11-04T14:00:30+00:00", success=True),
            make_record("2026-11-04T14:00:40+00:00"),
        ]
        result = detect_brute_force(records)
        self.assertEqual(result["total_failures"], 3)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(result["alerts"][0]["count"], 3)

    def test_success_only_input(self):
        result = detect_brute_force([make_record(success=True)])
        self.assertEqual(result["total_failures"], 0)
        self.assertEqual(result["failures_by_ip"], {})
        self.assertEqual(result["alerts"], [])

    def test_different_ips_are_not_combined(self):
        records = [
            make_record(),
            make_record("2026-11-04T14:00:20+00:00"),
            make_record("2026-11-04T14:00:40+00:00", source_ip="192.0.2.30"),
        ]
        result = detect_brute_force(records)
        self.assertEqual(result["total_failures"], 3)
        self.assertEqual(result["alerts"], [])

    def test_different_accounts_from_one_ip_are_combined(self):
        records = [
            make_record(username="alex"),
            make_record("2026-11-04T14:00:20+00:00", username="jordan"),
            make_record("2026-11-04T14:00:40+00:00", username="casey"),
        ]
        self.assertEqual(len(detect_brute_force(records)["alerts"]), 1)

    def test_exact_window_boundary_is_included(self):
        records = [
            make_record(),
            make_record("2026-11-04T14:00:20+00:00"),
            make_record("2026-11-04T14:01:00+00:00"),
        ]
        self.assertEqual(detect_brute_force(records)["alerts"][0]["count"], 3)

    def test_failure_just_outside_window_expires(self):
        records = [
            make_record(),
            make_record("2026-11-04T14:00:20+00:00"),
            make_record("2026-11-04T14:01:01+00:00"),
        ]
        result = detect_brute_force(records)
        self.assertEqual(result["alerts"], [])
        self.assertEqual(len(result["failures_by_ip"]["192.0.2.10"]), 2)

    def test_unordered_records_and_input_are_preserved(self):
        records = [
            make_record("2026-11-04T14:00:40+00:00"),
            make_record(),
            make_record("2026-11-04T14:00:20+00:00"),
        ]
        original = deepcopy(records)
        result = detect_brute_force(records)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(
            result["alerts"][0]["timestamp"],
            datetime(2026, 11, 4, 14, 0, 40, tzinfo=timezone.utc),
        )
        self.assertEqual(records, original)

    def test_mixed_timezone_offsets_are_compared_as_instants(self):
        records = [
            make_record("2026-11-04T09:00:40-05:00"),
            make_record("2026-11-04T14:00:00+00:00"),
            make_record("2026-11-04T15:00:20+01:00"),
        ]
        alert = detect_brute_force(records)["alerts"][0]
        self.assertEqual(alert["count"], 3)
        self.assertEqual(alert["timestamp"].isoformat(), "2026-11-04T14:00:40+00:00")

    def test_equivalent_ipv6_addresses_share_a_history(self):
        records = [
            make_record(source_ip="2001:db8::1"),
            make_record(source_ip="2001:0db8:0000:0000:0000:0000:0000:0001"),
            make_record(source_ip="2001:DB8::1"),
        ]
        result = detect_brute_force(records)
        self.assertEqual(list(result["failures_by_ip"]), ["2001:db8::1"])
        self.assertEqual(result["alerts"][0]["source_ip"], "2001:db8::1")

    def test_each_qualifying_failure_emits_an_alert(self):
        result = detect_brute_force([make_record() for _ in range(4)])
        self.assertEqual([alert["count"] for alert in result["alerts"]], [3, 4])

    def test_custom_threshold_and_window(self):
        records = [make_record(), make_record("2026-11-04T14:00:20+00:00")]
        self.assertEqual(
            len(detect_brute_force(records, failure_threshold=2)["alerts"]), 1
        )
        self.assertEqual(
            detect_brute_force(records, failure_threshold=2, window_seconds=19)["alerts"],
            [],
        )

    def test_rejects_invalid_configuration(self):
        for name in ("failure_threshold", "window_seconds"):
            for value in (0, -1, True, False, 1.5, "3", None):
                with self.subTest(name=name, value=value):
                    with self.assertRaisesRegex(ValueError, "positive integer"):
                        detect_brute_force([], **{name: value})

    def test_rejects_window_too_large_for_timedelta(self):
        with self.assertRaisesRegex(ValueError, "window_seconds is too large"):
            detect_brute_force([], window_seconds=10**30)

    def test_earliest_supported_timestamp_does_not_underflow(self):
        result = detect_brute_force(
            [make_record("0001-01-01T00:00:00+00:00")], failure_threshold=1
        )
        self.assertEqual(len(result["alerts"]), 1)

    def test_rejects_bad_timestamps_even_for_successful_logins(self):
        for timestamp in ("not-a-date", "2026-11-04T14:00:00", "0001-01-01T00:00:00+01:00"):
            with self.subTest(timestamp=timestamp):
                with self.assertRaisesRegex(ValueError, "Record 1: 'timestamp'"):
                    detect_brute_force([make_record(timestamp, success=True)])

    def test_rejects_invalid_ip_addresses(self):
        for address in ("999.1.2.3", "example.test", "192.0.2.10 "):
            with self.subTest(address=address):
                with self.assertRaisesRegex(ValueError, "valid IPv4 or IPv6"):
                    detect_brute_force([make_record(source_ip=address)])


class TestCommandLine(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.folder = Path(self.temporary_directory.name)
        self.script = Path(__file__).resolve().parent / "detector.py"
        self.input_path = self.folder / "records.json"
        self.input_path.write_text(
            json.dumps(
                [
                    make_record(),
                    make_record("2026-11-04T14:00:20+00:00"),
                    make_record("2026-11-04T14:00:40+00:00"),
                ]
            ),
            encoding="utf-8",
        )

    def run_detector(self, *arguments):
        return subprocess.run(
            [sys.executable, "-B", str(self.script), *map(str, arguments)],
            cwd=self.folder,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
        )

    def test_default_sample_works_from_another_directory(self):
        result = self.run_detector()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Total failed attempts: 4", result.stdout)
        self.assertIn("Total alerts: 0", result.stdout)

    def test_custom_settings_and_json_export(self):
        output_path = self.folder / "alerts.json"
        result = self.run_detector(
            self.input_path, "--threshold", 2, "--window", 30, "--output", output_path
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        alerts = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["source_ip"], "192.0.2.10")
        self.assertEqual(alerts[0]["count"], 2)
        self.assertEqual(alerts[0]["window_seconds"], 30)
        self.assertEqual(alerts[0]["timestamp"], "2026-11-04T14:00:20+00:00")
        self.assertEqual(alerts[1]["timestamp"], "2026-11-04T14:00:40+00:00")
        self.assertIn("Total alerts: 2", result.stdout)

    def test_exports_empty_list_when_no_alerts(self):
        output_path = self.folder / "alerts.json"
        result = self.run_detector(
            self.input_path, "--threshold", 4, "--output", output_path
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), [])

    def test_missing_input_is_reported(self):
        result = self.run_detector(self.folder / "missing.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("log file not found", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("Total failed attempts", result.stdout)

    def test_invalid_json_is_reported_with_line_number(self):
        self.input_path.write_text('[\n invalid\n]', encoding="utf-8")
        result = self.run_detector(self.input_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid JSON on line 2", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_utf8_is_reported(self):
        self.input_path.write_bytes(b'\xff')
        result = self.run_detector(self.input_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not read log file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_record_is_reported(self):
        self.input_path.write_text(json.dumps([make_record(success="false")]), encoding="utf-8")
        result = self.run_detector(self.input_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Record 1: 'success' must be a Boolean", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("Total failed attempts", result.stdout)

    def test_invalid_settings_are_usage_errors(self):
        for flag in ("--threshold", "--window"):
            for value in ("0", "-1", "1.5", "abc"):
                with self.subTest(flag=flag, value=value):
                    result = self.run_detector(self.input_path, flag, value)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("positive integer", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_input_cannot_be_used_as_output(self):
        original = self.input_path.read_bytes()
        result = self.run_detector(self.input_path, "--output", self.input_path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("different from the input", result.stderr)
        self.assertEqual(self.input_path.read_bytes(), original)

    def test_output_write_failure_is_reported(self):
        result = self.run_detector(self.input_path, "--output", self.folder)
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not write alerts", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("Total failed attempts", result.stdout)

    def test_help(self):
        result = self.run_detector("--help")
        self.assertEqual(result.returncode, 0)
        for flag in ("--threshold", "--window", "--output"):
            self.assertIn(flag, result.stdout)
