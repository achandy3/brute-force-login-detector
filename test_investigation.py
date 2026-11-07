"""Tests for opt-in incident grouping and batch investigation context."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from detector import detect_brute_force, export_alerts, export_incidents


def record_at(second, username="alex", source_ip="192.0.2.10", success=False):
    timestamp = datetime(2026, 11, 4, 14, tzinfo=timezone.utc) + timedelta(seconds=second)
    return {
        "timestamp": timestamp.isoformat(),
        "username": username,
        "source_ip": source_ip,
        "success": success,
    }


class TestIncidentGrouping(unittest.TestCase):
    def investigate(self, records, **settings):
        return detect_brute_force(records, investigate=True, **settings)

    def test_opt_in_preserves_original_fields_and_notification_behavior(self):
        records = [record_at(second) for second in (0, 10, 20, 30)]
        legacy = detect_brute_force(records)
        self.assertEqual(legacy, detect_brute_force(records, investigate=False))
        result = self.investigate(records)
        self.assertEqual(result["total_failures"], legacy["total_failures"])
        self.assertEqual(result["failures_by_ip"], legacy["failures_by_ip"])
        self.assertEqual(len(result["alerts"]), len(legacy["alerts"]))
        for original, enriched in zip(legacy["alerts"], result["alerts"]):
            self.assertEqual(original, {key: enriched[key] for key in original})
        self.assertNotIn("incidents", legacy)

    def test_one_incident_collects_accounts_times_and_notification_counts(self):
        records = [
            record_at(0), record_at(10, "jordan"), record_at(20), record_at(30, "casey")
        ]
        result = self.investigate(records)
        self.assertEqual(len(result["incidents"]), 1)
        incident = result["incidents"][0]
        self.assertEqual(incident["incident_id"], "INC-0001")
        self.assertEqual(incident["source_ip"], "192.0.2.10")
        self.assertEqual(incident["failure_count"], 4)
        self.assertEqual(incident["affected_usernames"], ["alex", "casey", "jordan"])
        self.assertEqual(incident["first_failure"].isoformat(), records[0]["timestamp"])
        self.assertEqual(incident["last_failure"].isoformat(), records[-1]["timestamp"])
        self.assertEqual(incident["first_detected"].isoformat(), records[2]["timestamp"])
        self.assertEqual(incident["peak_window_count"], 4)
        self.assertEqual(incident["alert_count"], 2)
        self.assertEqual(incident["suppressed_alert_count"], 0)
        self.assertEqual(incident["severity"], "medium")
        for alert in result["alerts"]:
            self.assertEqual(alert["incident_id"], incident["incident_id"])
            self.assertEqual(alert["incident_failure_count"], 4)
            self.assertEqual(alert["last_failure"], incident["last_failure"])
        self.assertEqual(result["alerts"][0]["count"], 3)

    def test_suppressed_events_still_enrich_the_incident(self):
        records = [record_at(second) for second in (0, 10, 20, 30, 40)]
        result = self.investigate(records, suppression_seconds=60)
        self.assertEqual(len(result["alerts"]), 1)
        incident = result["incidents"][0]
        self.assertEqual(incident["failure_count"], 5)
        self.assertEqual(incident["alert_count"], 1)
        self.assertEqual(incident["suppressed_alert_count"], 2)
        self.assertEqual(result["alerts"][0]["count"], 3)
        self.assertEqual(result["alerts"][0]["incident_failure_count"], 5)
        self.assertEqual(
            result["alerts"][0]["last_failure"].isoformat(), records[-1]["timestamp"]
        )

    def test_gap_beyond_window_starts_a_new_incident(self):
        records = [record_at(second) for second in (0, 10, 20, 81, 91, 101)]
        result = self.investigate(records)
        self.assertEqual([item["failure_count"] for item in result["incidents"]], [3, 3])
        self.assertEqual(
            [alert["incident_id"] for alert in result["alerts"]], ["INC-0001", "INC-0002"]
        )
        self.assertEqual(
            result["incidents"][1]["first_failure"].isoformat(), records[3]["timestamp"]
        )

    def test_exact_gap_boundary_and_subthreshold_continuation_stay_in_incident(self):
        records = [record_at(second) for second in (0, 10, 20, 80, 140)]
        result = self.investigate(records)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["failure_count"], 5)
        self.assertEqual(result["incidents"][0]["peak_window_count"], 3)
        self.assertEqual(len(result["alerts"]), 1)

    def test_old_prelude_outside_first_qualifying_window_is_excluded(self):
        records = [record_at(second) for second in (0, 70, 80, 90)]
        result = self.investigate(records)
        self.assertEqual(result["total_failures"], 4)
        self.assertEqual(result["incidents"][0]["failure_count"], 3)
        self.assertEqual(
            result["incidents"][0]["first_failure"].isoformat(), records[1]["timestamp"]
        )

    def test_empty_success_only_and_subthreshold_input_have_no_incidents(self):
        for records in ([], [record_at(0, success=True)], [record_at(0), record_at(90)]):
            with self.subTest(records=records):
                result = self.investigate(records)
                self.assertEqual(result["incidents"], [])
                self.assertEqual(result["alerts"], [])

    def test_later_subthreshold_session_does_not_extend_previous_incident(self):
        records = [record_at(second) for second in (0, 10, 20, 100)]
        result = self.investigate(records)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["failure_count"], 3)
        self.assertEqual(result["incidents"][0]["last_failure"].isoformat(), records[2]["timestamp"])

    def test_wholly_suppressed_incident_is_still_reported(self):
        records = [record_at(second) for second in (0, 10, 20, 100, 110, 120)]
        result = self.investigate(records, suppression_seconds=300)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(len(result["incidents"]), 2)
        second = result["incidents"][1]
        self.assertEqual(second["alert_count"], 0)
        self.assertEqual(second["suppressed_alert_count"], 1)
        self.assertEqual(second["failure_count"], 3)

    def test_periodic_notifications_still_belong_to_one_incident(self):
        records = [record_at(second) for second in (0, 10, 20, 40, 60, 80)]
        result = self.investigate(records, suppression_seconds=60)
        self.assertEqual(len(result["alerts"]), 2)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual({alert["incident_id"] for alert in result["alerts"]}, {"INC-0001"})
        self.assertEqual(result["incidents"][0]["alert_count"], 2)
        self.assertEqual(result["incidents"][0]["suppressed_alert_count"], 2)

    def test_ips_and_accounts_are_grouped_independently(self):
        records = [record_at(second) for second in (0, 10, 20)]
        records += [record_at(second, "jordan", "192.0.2.30") for second in (0, 10, 20)]
        result = self.investigate(records)
        self.assertEqual(len(result["incidents"]), 2)
        self.assertEqual(
            {item["source_ip"]: item["affected_usernames"] for item in result["incidents"]},
            {"192.0.2.10": ["alex"], "192.0.2.30": ["jordan"]},
        )

    def test_correlated_success_can_upgrade_a_wholly_suppressed_incident(self):
        records = [record_at(second) for second in (0, 10, 20, 100, 110, 120)]
        records.append(record_at(125, success=True))
        result = self.investigate(records, suppression_seconds=300)
        first, second = result["incidents"]
        self.assertFalse(first["successful_login_after_failures"])
        self.assertTrue(second["successful_login_after_failures"])
        self.assertEqual(second["severity"], "high")
        self.assertEqual(second["alert_count"], 0)
        self.assertEqual(len(result["alerts"]), 1)

    def test_rejects_non_boolean_investigation_option(self):
        for value in (0, 1, "true", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "investigate must be a Boolean"):
                    detect_brute_force([], investigate=value)


class TestInvestigationContext(unittest.TestCase):
    def investigate(self, extra_records=(), **settings):
        records = [record_at(second) for second in (0, 10, 20)]
        records.extend(extra_records)
        return detect_brute_force(records, investigate=True, **settings)

    def test_success_after_detection_enriches_alert_with_batch_context(self):
        result = self.investigate([record_at(25, success=True), record_at(40)])
        incident = result["incidents"][0]
        alert = result["alerts"][0]
        self.assertTrue(incident["successful_login_after_failures"])
        self.assertEqual(incident["severity"], "high")
        self.assertEqual(incident["successful_logins"][0]["username"], "alex")
        self.assertEqual(incident["successful_logins"][0]["timestamp"].second, 25)
        self.assertTrue(alert["successful_login_after_failures"])
        self.assertEqual(alert["count"], 3)
        self.assertEqual(alert["timestamp"].second, 20)
        self.assertEqual(alert["last_failure"].second, 40)
        self.assertIn("after detection", " ".join(alert["severity_reasons"]))

    def test_success_before_detection_is_not_correlated(self):
        records = [record_at(0), record_at(10, success=True), record_at(20), record_at(40)]
        result = detect_brute_force(records, investigate=True)
        self.assertFalse(result["incidents"][0]["successful_login_after_failures"])
        self.assertEqual(result["incidents"][0]["severity"], "medium")

    def test_success_at_detection_time_is_not_after_detection(self):
        for order in (
            [record_at(20), record_at(20, success=True)],
            [record_at(20, success=True), record_at(20)],
        ):
            with self.subTest(order=order):
                result = detect_brute_force([record_at(0), record_at(10)] + order, investigate=True)
                self.assertFalse(result["incidents"][0]["successful_login_after_failures"])

    def test_unrelated_ip_or_account_is_not_correlated(self):
        for success in (
            record_at(25, source_ip="192.0.2.30", success=True),
            record_at(25, username="jordan", success=True),
        ):
            with self.subTest(success=success):
                result = self.investigate([success])
                self.assertFalse(result["incidents"][0]["successful_login_after_failures"])
                self.assertEqual(result["incidents"][0]["severity"], "medium")

    def test_later_failure_does_not_retroactively_match_an_earlier_success(self):
        result = self.investigate([record_at(25, "jordan", success=True), record_at(30, "jordan")])
        self.assertIn("jordan", result["incidents"][0]["affected_usernames"])
        self.assertFalse(result["incidents"][0]["successful_login_after_failures"])

    def test_success_correlation_window_boundary(self):
        for second, expected in ((80, True), (81, False)):
            with self.subTest(second=second):
                result = self.investigate([record_at(second, success=True)])
                self.assertEqual(
                    result["incidents"][0]["successful_login_after_failures"], expected
                )

    def test_success_must_follow_a_recent_failure_of_that_specific_account(self):
        records = [
            record_at(0), record_at(10, "jordan"), record_at(20, "jordan"),
            record_at(50, "jordan"),
        ]
        result = detect_brute_force(records + [record_at(61, success=True)], investigate=True)
        self.assertFalse(result["incidents"][0]["successful_login_after_failures"])
        result = detect_brute_force(records + [record_at(60, success=True)], investigate=True)
        self.assertTrue(result["incidents"][0]["successful_login_after_failures"])

    def test_tied_events_are_independent_of_input_order(self):
        prefix = [record_at(0), record_at(10), record_at(20, "jordan")]
        tied = [record_at(30), record_at(30, success=True)]
        first = detect_brute_force(prefix + tied, investigate=True)
        second = detect_brute_force(list(reversed(prefix + tied)), investigate=True)
        self.assertEqual(first, second)
        self.assertTrue(first["incidents"][0]["successful_login_after_failures"])

    def test_unordered_offsets_are_normalized_without_mutating_input(self):
        records = [record_at(0), record_at(10), record_at(20), record_at(25, success=True)]
        records[3]["timestamp"] = "2026-11-04T09:00:25-05:00"
        records.reverse()
        original = deepcopy(records)
        result = detect_brute_force(records, investigate=True)
        self.assertEqual(
            result["incidents"][0]["first_failure"].isoformat(), record_at(0)["timestamp"]
        )
        self.assertEqual(
            result["incidents"][0]["successful_logins"][0]["timestamp"].isoformat(),
            record_at(25)["timestamp"],
        )
        self.assertEqual(records, original)

    def test_ipv6_equivalents_share_an_incident_and_success_context(self):
        records = [record_at(second, source_ip="2001:db8::1") for second in (0, 10, 20)]
        records.append(
            record_at(25, source_ip="2001:0db8:0000:0000:0000:0000:0000:0001", success=True)
        )
        result = detect_brute_force(records, investigate=True)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["source_ip"], "2001:db8::1")
        self.assertTrue(result["incidents"][0]["successful_login_after_failures"])

    def test_peak_rolling_count_drives_volume_severity(self):
        for threshold, count, expected in (
            (3, 5, "medium"), (3, 6, "high"), (2, 4, "high"), (4, 6, "medium")
        ):
            with self.subTest(threshold=threshold, count=count):
                records = [record_at(second) for second in range(count)]
                result = detect_brute_force(records, failure_threshold=threshold, investigate=True)
                self.assertEqual(result["incidents"][0]["severity"], expected)
                self.assertEqual(result["incidents"][0]["peak_window_count"], count)

    def test_cumulative_count_alone_does_not_raise_severity(self):
        records = [record_at(second) for second in (0, 20, 40, 80, 100, 140)]
        incident = detect_brute_force(records, investigate=True)["incidents"][0]
        self.assertEqual(incident["failure_count"], 6)
        self.assertEqual(incident["peak_window_count"], 3)
        self.assertEqual(incident["severity"], "medium")

    def test_alert_context_does_not_alias_other_alerts_or_incidents(self):
        result = self.investigate([record_at(25, success=True), record_at(30)])
        result["alerts"][0]["affected_usernames"].append("edited")
        result["alerts"][0]["successful_logins"][0]["username"] = "edited"
        for untouched in (result["alerts"][1], result["incidents"][0]):
            self.assertEqual(untouched["affected_usernames"], ["alex"])
            self.assertEqual(untouched["successful_logins"][0]["username"], "alex")

    def test_export_serializes_nested_dates_without_mutating_results(self):
        result = self.investigate([record_at(25, success=True)])
        original = deepcopy(result)
        with tempfile.TemporaryDirectory() as directory:
            alerts_path = Path(directory) / "alerts.json"
            incidents_path = Path(directory) / "incidents.json"
            export_alerts(result["alerts"], alerts_path)
            export_incidents(result["incidents"], incidents_path)
            for path in (alerts_path, incidents_path):
                report = json.loads(path.read_text(encoding="utf-8"))[0]
                self.assertEqual(report["first_failure"], record_at(0)["timestamp"])
                self.assertEqual(
                    report["successful_logins"][0]["timestamp"], record_at(25)["timestamp"]
                )
                self.assertTrue(report["successful_login_after_failures"])
                self.assertEqual(report["severity"], "high")
        self.assertEqual(result, original)


class TestInvestigationCommandLine(unittest.TestCase):
    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.folder = Path(temporary_directory.name)
        self.script = Path(__file__).resolve().parent / "detector.py"
        self.input_path = self.folder / "records.json"
        self.input_path.write_text(
            json.dumps(
                [record_at(second) for second in (0, 10, 20, 30)]
                + [record_at(35, success=True)]
            ),
            encoding="utf-8",
        )

    def run_detector(self, *arguments):
        return subprocess.run(
            [sys.executable, "-B", str(self.script), str(self.input_path), *map(str, arguments)],
            cwd=self.folder, capture_output=True, text=True, encoding="utf-8", timeout=10,
        )

    def test_investigation_console_and_both_reports(self):
        alerts_path = self.folder / "alerts.json"
        incidents_path = self.folder / "incidents.json"
        result = self.run_detector(
            "--investigate", "--suppression-seconds", 60,
            "--output", alerts_path, "--incidents-output", incidents_path,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Total alerts: 1", result.stdout)
        self.assertIn("Total incidents: 1", result.stdout)
        self.assertIn("Severity: high", result.stdout)
        self.assertIn("Affected accounts: alex", result.stdout)
        self.assertIn("Successful login after failures: True", result.stdout)
        alert = json.loads(alerts_path.read_text(encoding="utf-8"))[0]
        incident = json.loads(incidents_path.read_text(encoding="utf-8"))[0]
        self.assertEqual(alert["incident_id"], incident["incident_id"])
        self.assertEqual(alert["count"], 3)
        self.assertEqual(alert["incident_failure_count"], 4)
        self.assertEqual(incident["failure_count"], 4)
        self.assertEqual(incident["suppressed_alert_count"], 1)
        self.assertTrue(incident["successful_login_after_failures"])

    def test_incident_output_requires_investigation_mode(self):
        result = self.run_detector("--incidents-output", self.folder / "incidents.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --investigate", result.stderr)

    def test_incident_report_cannot_overwrite_input(self):
        original = self.input_path.read_bytes()
        result = self.run_detector("--investigate", "--incidents-output", self.input_path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("different from the input", result.stderr)
        self.assertEqual(self.input_path.read_bytes(), original)

    def test_alert_and_incident_reports_need_distinct_paths(self):
        path = self.folder / "same.json"
        result = self.run_detector("--investigate", "--output", path, "--incidents-output", path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("paths must be different", result.stderr)
        self.assertFalse(path.exists())

    def test_incident_export_failure_is_reported(self):
        result = self.run_detector("--investigate", "--incidents-output", self.folder)
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not write incidents", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("Total incidents", result.stdout)

    def test_empty_input_exports_empty_incident_and_alert_lists(self):
        self.input_path.write_text("[]", encoding="utf-8")
        alerts_path = self.folder / "alerts.json"
        incidents_path = self.folder / "incidents.json"
        result = self.run_detector(
            "--investigate", "--output", alerts_path, "--incidents-output", incidents_path
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in (alerts_path, incidents_path):
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), [])

    def test_help_lists_investigation_options(self):
        result = self.run_detector("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--investigate", result.stdout)
        self.assertIn("--incidents-output", result.stdout)
