from copy import deepcopy
from datetime import datetime, timedelta, timezone
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


class TestAlertSuppression(unittest.TestCase):
    def failures_at(self, *seconds, source_ip="192.0.2.10"):
        start = datetime(2026, 11, 4, 14, tzinfo=timezone.utc)
        return [
            make_record(
                (start + timedelta(seconds=second)).isoformat(), source_ip=source_ip
            )
            for second in seconds
        ]

    def test_zero_preserves_original_alerts_and_result_shape(self):
        records = self.failures_at(0, 10, 20, 30, 40)
        original = detect_brute_force(records)
        explicit_zero = detect_brute_force(records, suppression_seconds=0)
        self.assertEqual(original, explicit_zero)
        self.assertEqual([alert["count"] for alert in original["alerts"]], [3, 4, 5])
        self.assertEqual(
            set(original), {"total_failures", "failures_by_ip", "alerts"}
        )
        self.assertEqual(
            set(original["alerts"][0]),
            {"source_ip", "count", "window_seconds", "timestamp"},
        )

    def test_suppressed_failures_still_count_without_updating_alert_snapshot(self):
        records = self.failures_at(0, 10, 20, 30, 40)
        original_records = deepcopy(records)
        original_result = detect_brute_force(records)
        result = detect_brute_force(records, suppression_seconds=60)
        self.assertEqual(result["alerts"], [original_result["alerts"][0]])
        self.assertEqual(result["total_failures"], 5)
        self.assertEqual(
            result["failures_by_ip"], original_result["failures_by_ip"]
        )
        self.assertEqual(result["alerts"][0]["count"], 3)
        self.assertEqual(records, original_records)

    def test_cooldown_boundary(self):
        for last_second, expected_alerts in ((79, 1), (80, 2), (81, 2)):
            with self.subTest(last_second=last_second):
                records = self.failures_at(0, 10, 20, last_second)
                result = detect_brute_force(
                    records, window_seconds=120, suppression_seconds=60
                )
                self.assertEqual(len(result["alerts"]), expected_alerts)

    def test_suppressed_events_do_not_extend_cooldown(self):
        records = self.failures_at(0, 10, 20, 30, 79, 80, 139, 140)
        result = detect_brute_force(
            records, window_seconds=300, suppression_seconds=60
        )
        self.assertEqual(
            [alert["timestamp"].isoformat() for alert in result["alerts"]],
            [
                "2026-11-04T14:00:20+00:00",
                "2026-11-04T14:01:20+00:00",
                "2026-11-04T14:02:20+00:00",
            ],
        )
        self.assertEqual([alert["count"] for alert in result["alerts"]], [3, 6, 8])

    def test_cooldowns_are_independent_for_each_ip(self):
        records = self.failures_at(0, 10, 20, 30)
        records += self.failures_at(0, 10, 20, 30, source_ip="192.0.2.30")
        result = detect_brute_force(records, suppression_seconds=60)
        self.assertEqual(len(result["alerts"]), 2)
        self.assertEqual(
            {alert["source_ip"] for alert in result["alerts"]},
            {"192.0.2.10", "192.0.2.30"},
        )
        self.assertEqual(result["total_failures"], 8)

    def test_equivalent_ipv6_addresses_share_a_cooldown(self):
        records = self.failures_at(0, 10, 20, source_ip="2001:db8::1")
        records += self.failures_at(
            30, source_ip="2001:0db8:0000:0000:0000:0000:0000:0001"
        )
        result = detect_brute_force(records, suppression_seconds=60)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(result["alerts"][0]["source_ip"], "2001:db8::1")
        self.assertEqual(len(result["failures_by_ip"]["2001:db8::1"]), 4)

    def test_cooldown_uses_sorted_event_time_across_timezones(self):
        records = [
            make_record("2026-11-04T09:01:20-05:00"),
            make_record("2026-11-04T14:00:20+00:00"),
            make_record(),
            make_record("2026-11-04T14:00:10+00:00"),
            make_record("2026-11-04T15:01:19+01:00"),
        ]
        original = deepcopy(records)
        result = detect_brute_force(
            records, window_seconds=120, suppression_seconds=60
        )
        self.assertEqual(
            [alert["timestamp"].isoformat() for alert in result["alerts"]],
            ["2026-11-04T14:00:20+00:00", "2026-11-04T14:01:20+00:00"],
        )
        self.assertEqual(records, original)

    def test_successful_login_does_not_reset_cooldown(self):
        records = self.failures_at(0, 10, 20, 40, 80)
        records.append(make_record("2026-11-04T14:00:30+00:00", success=True))
        result = detect_brute_force(
            records, window_seconds=120, suppression_seconds=60
        )
        self.assertEqual(result["total_failures"], 5)
        self.assertEqual([alert["count"] for alert in result["alerts"]], [3, 5])

    def test_new_burst_within_cooldown_is_suppressed_but_later_burst_alerts(self):
        records = self.failures_at(0, 10, 20, 100, 110, 120, 300, 310, 320)
        result = detect_brute_force(records, suppression_seconds=300)
        self.assertEqual(
            [alert["timestamp"].isoformat() for alert in result["alerts"]],
            ["2026-11-04T14:00:20+00:00", "2026-11-04T14:05:20+00:00"],
        )
        self.assertEqual([alert["count"] for alert in result["alerts"]], [3, 3])
        self.assertEqual(result["total_failures"], 9)
        self.assertEqual(len(result["failures_by_ip"]["192.0.2.10"]), 3)

    def test_suppression_does_not_create_alerts_below_threshold(self):
        result = detect_brute_force(self.failures_at(0, 10), suppression_seconds=60)
        self.assertEqual(result["alerts"], [])
        self.assertEqual(detect_brute_force([], suppression_seconds=60)["alerts"], [])

    def test_zero_allows_alerts_at_the_same_timestamp(self):
        records = self.failures_at(0, 0, 0, 0)
        self.assertEqual(
            len(detect_brute_force(records, suppression_seconds=0)["alerts"]), 2
        )
        self.assertEqual(
            len(detect_brute_force(records, suppression_seconds=1)["alerts"]), 1
        )

    def test_rejects_invalid_suppression_configuration(self):
        for value in (-1, True, False, 1.5, "60", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "nonnegative integer"):
                    detect_brute_force([], suppression_seconds=value)
        with self.assertRaisesRegex(ValueError, "suppression_seconds is too large"):
            detect_brute_force([], suppression_seconds=10**30)


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

    def test_suppression_option_filters_console_and_exported_alerts(self):
        output_path = self.folder / "alerts.json"
        result = self.run_detector(
            self.input_path,
            "--threshold", 2,
            "--suppression-seconds", 60,
            "--output", output_path,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        alerts = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 2)
        self.assertEqual(alerts[0]["timestamp"], "2026-11-04T14:00:20+00:00")
        self.assertIn("Total failed attempts: 3", result.stdout)
        self.assertIn("Total alerts: 1", result.stdout)
        self.assertEqual(result.stdout.count("[ALERT]"), 1)

    def test_explicit_zero_suppression_keeps_original_cli_behavior(self):
        result = self.run_detector(
            self.input_path, "--threshold", 2, "--suppression-seconds", 0
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Total alerts: 2", result.stdout)
        self.assertEqual(result.stdout.count("[ALERT]"), 2)

    def test_invalid_suppression_arguments_are_reported(self):
        for value in ("-1", "1.5", "abc"):
            with self.subTest(value=value):
                result = self.run_detector(
                    self.input_path, "--suppression-seconds", value
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("nonnegative integer", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_suppression_duration_overflow_is_reported(self):
        result = self.run_detector(
            self.input_path, "--suppression-seconds", 10**30
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("suppression_seconds is too large", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

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
        for flag in ("--threshold", "--window", "--suppression-seconds", "--output"):
            self.assertIn(flag, result.stdout)
