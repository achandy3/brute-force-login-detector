"""Analyze simulated authentication logs for possible brute-force attempts."""

import argparse
import json
from collections import deque
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path


def validate_records(records) -> None:
    """Reject malformed records before processing any login attempts."""
    if not isinstance(records, list):
        raise ValueError("Login data must be a list.")

    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"Record {index} must be an object.")

        for field in ("timestamp", "username", "source_ip", "success"):
            if field not in record:
                raise ValueError(f"Record {index} is missing '{field}'.")

        for field in ("timestamp", "username", "source_ip"):
            value = record[field]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Record {index}: '{field}' must be a nonempty string."
                )

        if not isinstance(record["success"], bool):
            raise ValueError(f"Record {index}: 'success' must be a Boolean.")

        try:
            timestamp = datetime.fromisoformat(record["timestamp"])
        except ValueError:
            raise ValueError(
                f"Record {index}: 'timestamp' must be an ISO 8601 date and time."
            ) from None

        if timestamp.utcoffset() is None:
            raise ValueError(
                f"Record {index}: 'timestamp' must include a timezone offset."
            )

        try:
            timestamp.astimezone(timezone.utc)
        except (OverflowError, ValueError):
            raise ValueError(
                f"Record {index}: 'timestamp' is outside the supported UTC range."
            ) from None

        try:
            ip_address(record["source_ip"])
        except ValueError:
            raise ValueError(
                f"Record {index}: 'source_ip' must be a valid IPv4 or IPv6 address."
            ) from None


def _add_investigation_context(records, alerts, failure_threshold, time_window):
    """Group suspicious failure sessions and enrich emitted alerts after the batch.

    Successful events are processed before failures at the same instant so a
    correlation always uses strictly earlier evidence, independent of input order.
    """
    events = [
        {
            "timestamp": datetime.fromisoformat(record["timestamp"]).astimezone(
                timezone.utc
            ),
            "source_ip": str(ip_address(record["source_ip"])),
            "username": record["username"],
            "success": record["success"],
        }
        for record in records
    ]
    events.sort(
        key=lambda event: (
            event["timestamp"], not event["success"],
            event["source_ip"], event["username"],
        )
    )
    alerts_by_event = {
        (alert["source_ip"], alert["timestamp"], alert["count"]): alert
        for alert in alerts
    }
    recent_failures = {}
    active_by_ip = {}
    states = []
    associations = []

    for event in events:
        timestamp = event["timestamp"]
        source_ip = event["source_ip"]
        username = event["username"]
        state = active_by_ip.get(source_ip)

        if event["success"]:
            if state is not None:
                incident = state["incident"]
                last_failure = state["last_failure_by_user"].get(username)
                if (
                    last_failure is not None
                    and timestamp > incident["first_detected"]
                    and timedelta(0) < timestamp - last_failure <= time_window
                ):
                    incident["successful_logins"].append(
                        {"username": username, "timestamp": timestamp}
                    )
            continue

        recent = recent_failures.setdefault(source_ip, deque())
        recent.append(event)
        while recent and timestamp - recent[0]["timestamp"] > time_window:
            recent.popleft()
        count = len(recent)

        if state is not None:
            if timestamp - state["incident"]["last_failure"] > time_window:
                del active_by_ip[source_ip]
                state = None

        if state is None:
            if count < failure_threshold:
                continue
            incident = {
                "incident_id": f"INC-{len(states) + 1:04d}",
                "source_ip": source_ip,
                "failure_count": count,
                "first_failure": recent[0]["timestamp"],
                "last_failure": timestamp,
                "first_detected": timestamp,
                "window_seconds": int(time_window.total_seconds()),
                "peak_window_count": count,
                "alert_count": 0,
                "suppressed_alert_count": 0,
                "successful_logins": [],
            }
            state = {
                "incident": incident,
                "last_failure_by_user": {
                    failure["username"]: failure["timestamp"] for failure in recent
                },
            }
            active_by_ip[source_ip] = state
            states.append(state)
        else:
            incident = state["incident"]
            incident["failure_count"] += 1
            incident["last_failure"] = timestamp
            incident["peak_window_count"] = max(incident["peak_window_count"], count)
            state["last_failure_by_user"][username] = timestamp

        if count >= failure_threshold:
            alert = alerts_by_event.get((source_ip, timestamp, count))
            if alert is None:
                incident["suppressed_alert_count"] += 1
            else:
                incident["alert_count"] += 1
                associations.append((alert, incident))

    incidents = []
    for state in states:
        incident = state["incident"]
        incident["affected_usernames"] = sorted(state["last_failure_by_user"])
        incident["successful_login_after_failures"] = bool(incident["successful_logins"])
        reasons = ["Rolling-window failure threshold reached."]
        severity = "medium"
        if incident["peak_window_count"] >= 2 * failure_threshold:
            severity = "high"
            reasons.append("Peak rolling-window count reached twice the threshold.")
        if incident["successful_login_after_failures"]:
            severity = "high"
            reasons.append("A targeted account logged in successfully after detection.")
        incident["severity"] = severity
        incident["severity_reasons"] = reasons
        incidents.append(incident)

    for alert, incident in associations:
        alert["incident_id"] = incident["incident_id"]
        alert["incident_failure_count"] = incident["failure_count"]
        for field in (
            "affected_usernames", "first_failure", "last_failure", "first_detected",
            "peak_window_count", "successful_login_after_failures", "successful_logins",
            "severity", "severity_reasons",
        ):
            alert[field] = deepcopy(incident[field])
    return incidents


def detect_brute_force(
    login_records, failure_threshold=3, window_seconds=60, *,
    suppression_seconds=0, investigate=False,
):
    """Return alerts meeting the per-IP rolling-window rule and optional cooldown.

    Records are validated and processed in chronological order. The window
    includes both endpoints, successful logins do not reset failures, and the
    input records are not modified. Returned timestamps are UTC datetimes.
    A positive suppression_seconds limits each IP to one emitted alert per
    cooldown, measured from its last emitted alert's event time. Suppressed
    alerts do not extend the cooldown or affect failure counts. Zero preserves
    the original behavior of emitting every qualifying failure.
    investigate=True adds incident summaries and final-batch context to alerts;
    the default preserves the original return structure and alert schema.
    """

    for name, value in (
        ("failure_threshold", failure_threshold),
        ("window_seconds", window_seconds),
    ):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer.")

    if type(suppression_seconds) is not int or suppression_seconds < 0:
        raise ValueError("suppression_seconds must be a nonnegative integer.")
    if type(investigate) is not bool:
        raise ValueError("investigate must be a Boolean.")

    try:
        time_window = timedelta(seconds=window_seconds)
    except OverflowError:
        raise ValueError("window_seconds is too large.") from None

    try:
        suppression_window = timedelta(seconds=suppression_seconds)
    except OverflowError:
        raise ValueError("suppression_seconds is too large.") from None

    validate_records(login_records)

    ordered_records = sorted(
        login_records,
        key=lambda record: datetime.fromisoformat(record["timestamp"]),
    )

    failed_count = 0
    failures_by_ip = {}
    alerts = []
    last_alert_by_ip = {}

    for record in ordered_records:
        if not record["success"]:
            failed_count += 1
            timestamp = datetime.fromisoformat(record["timestamp"]).astimezone(
                timezone.utc
            )
            source_ip = str(ip_address(record["source_ip"]))

            if source_ip not in failures_by_ip:
                failures_by_ip[source_ip] = deque()

            timestamps = failures_by_ip[source_ip]
            timestamps.append(timestamp)

            # Chronological processing keeps the oldest failure at the front.
            # Comparing durations also avoids subtracting past datetime.min.
            while timestamps and timestamp - timestamps[0] > time_window:
                timestamps.popleft()

            count = len(timestamps)

            if count >= failure_threshold:
                last_alert_time = last_alert_by_ip.get(source_ip)
                if (
                    last_alert_time is not None
                    and timestamp - last_alert_time < suppression_window
                ):
                    continue

                alerts.append(
                    {
                        "source_ip": source_ip,
                        "count": count,
                        "window_seconds": window_seconds,
                        "timestamp": timestamp,
                    }
                )
                last_alert_by_ip[source_ip] = timestamp

    result = {
        "total_failures": failed_count,
        "failures_by_ip": {
            source_ip: list(timestamps)
            for source_ip, timestamps in failures_by_ip.items()
        },
        "alerts": alerts,
    }
    if investigate:
        result["incidents"] = _add_investigation_context(
            ordered_records, alerts, failure_threshold, time_window
        )
    return result


def _json_datetime(value):
    """Convert datetimes anywhere in a report without hiding unsupported types."""
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Cannot serialize {type(value).__name__} as JSON.")


def _export_report(records, output_path) -> None:
    with Path(output_path).open("w", encoding="utf-8") as output_file:
        json.dump(records, output_file, indent=4, default=_json_datetime)
        output_file.write("\n")


def export_alerts(alerts, output_path) -> None:
    """Write legacy or enriched alerts as JSON without modifying the input."""
    _export_report(alerts, output_path)


def export_incidents(incidents, output_path) -> None:
    """Write complete incident summaries, including incidents without notifications."""
    _export_report(incidents, output_path)


def positive_integer(value):
    """Convert a command-line argument to a strictly positive integer."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def nonnegative_integer(value):
    """Convert a command-line argument to an integer greater than or equal to zero."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a nonnegative integer") from None
    if number < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return number


def build_parser():
    """Describe the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Detect repeated failed logins from simulated JSON records.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent / "sample_logs.json",
        help="JSON file containing login records",
    )
    parser.add_argument(
        "--threshold",
        type=positive_integer,
        default=3,
        help="minimum failed attempts from one IP needed for an alert",
    )
    parser.add_argument(
        "--window",
        type=positive_integer,
        default=60,
        help="rolling time window in seconds (inclusive)",
    )
    parser.add_argument(
        "--suppression-seconds",
        type=nonnegative_integer,
        default=0,
        help="minimum seconds between alerts from the same IP; 0 disables suppression",
    )
    parser.add_argument(
        "--investigate",
        action="store_true",
        help="add grouped incidents, affected accounts, related successes, and severity",
    )
    parser.add_argument(
        "--incidents-output",
        type=Path,
        help="write complete incident summaries as JSON (requires --investigate)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write alerts as JSON to this file; its parent directory must exist",
    )
    return parser


def main(argv=None) -> int:
    """Load records, run detection, and display or export the results."""
    parser = build_parser()
    args = parser.parse_args(argv)
    log_path = args.log_file

    if args.incidents_output is not None and not args.investigate:
        parser.error("--incidents-output requires --investigate")
    for flag, output_path in (
        ("--output", args.output), ("--incidents-output", args.incidents_output)
    ):
        if output_path is not None and output_path.resolve() == log_path.resolve():
            parser.error(f"{flag} must be different from the input log file")
    if (
        args.output is not None and args.incidents_output is not None
        and args.output.resolve() == args.incidents_output.resolve()
    ):
        parser.error("alert and incident output paths must be different")

    try:
        with log_path.open("r", encoding="utf-8") as log_file:
            login_records = json.load(log_file)
    except FileNotFoundError:
        parser.exit(1, f"Error: log file not found: {log_path}\n")
    except json.JSONDecodeError as error:
        parser.exit(1, f"Error: invalid JSON on line {error.lineno}: {error.msg}\n")
    except (OSError, UnicodeError) as error:
        parser.exit(1, f"Error: could not read log file: {error}\n")

    try:
        result = detect_brute_force(
            login_records,
            args.threshold,
            args.window,
            suppression_seconds=args.suppression_seconds,
            investigate=args.investigate,
        )
    except ValueError as error:
        parser.exit(1, f"Error: invalid login data: {error}\n")

    if args.output is not None:
        try:
            export_alerts(result["alerts"], args.output)
        except (OSError, UnicodeError) as error:
            parser.exit(1, f"Error: could not write alerts: {error}\n")
    if args.incidents_output is not None:
        try:
            export_incidents(result["incidents"], args.incidents_output)
        except (OSError, UnicodeError) as error:
            parser.exit(1, f"Error: could not write incidents: {error}\n")

    print("Brute-Force Login Detector ready.")
    print(f"Total failed attempts: {result['total_failures']}")
    print(f"Total alerts: {len(result['alerts'])}")
    if args.investigate:
        print(f"Total incidents: {len(result['incidents'])}")

    for source_ip, timestamps in sorted(result["failures_by_ip"].items()):
        count = len(timestamps)
        print(
            f"Source IP: {source_ip}, "
            f"Failures in window at latest failure: {count}"
        )

    for alert in result["alerts"]:
        message = (
            f"[ALERT] Possible brute-force activity: "
            f"Source IP: {alert['source_ip']}, Count: {alert['count']}, "
            f"Window: {alert['window_seconds']} seconds, "
            f"Time: {alert['timestamp'].isoformat()}"
        )
        if args.investigate:
            message += f", Incident: {alert['incident_id']}, Severity: {alert['severity']}"
        print(message)

    if args.investigate:
        for incident in result["incidents"]:
            print(
                f"[INCIDENT] {incident['incident_id']}, Source IP: {incident['source_ip']}, "
                f"Severity: {incident['severity']}, Failures: {incident['failure_count']}, "
                f"Peak window count: {incident['peak_window_count']}, "
                f"Alerts: {incident['alert_count']}, "
                f"Suppressed: {incident['suppressed_alert_count']}"
            )
            print(f"  Affected accounts: {', '.join(incident['affected_usernames'])}")
            print(
                f"  First failure: {incident['first_failure'].isoformat()}, "
                f"Last failure: {incident['last_failure'].isoformat()}, "
                f"Successful login after failures: "
                f"{incident['successful_login_after_failures']}"
            )

    if args.output is not None:
        print(f"Alerts written to: {args.output}")
    if args.incidents_output is not None:
        print(f"Incidents written to: {args.incidents_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
