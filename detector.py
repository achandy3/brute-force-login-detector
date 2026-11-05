"""Analyze simulated authentication logs for possible brute-force attempts."""

import argparse
import json
from collections import deque
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


def detect_brute_force(login_records, failure_threshold=3, window_seconds=60):
    """Return alerts for each failure meeting the per-IP rolling-window rule.

    Records are validated and processed in chronological order. The window
    includes both endpoints, successful logins do not reset failures, and the
    input records are not modified. Returned timestamps are UTC datetimes.
    """

    for name, value in (
        ("failure_threshold", failure_threshold),
        ("window_seconds", window_seconds),
    ):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer.")

    try:
        time_window = timedelta(seconds=window_seconds)
    except OverflowError:
        raise ValueError("window_seconds is too large.") from None

    validate_records(login_records)

    ordered_records = sorted(
        login_records,
        key=lambda record: datetime.fromisoformat(record["timestamp"]),
    )

    failed_count = 0
    failures_by_ip = {}
    alerts = []

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
                alerts.append(
                    {
                        "source_ip": source_ip,
                        "count": count,
                        "window_seconds": window_seconds,
                        "timestamp": timestamp,
                    }
                )

    return {
        "total_failures": failed_count,
        "failures_by_ip": {
            source_ip: list(timestamps)
            for source_ip, timestamps in failures_by_ip.items()
        },
        "alerts": alerts,
    }


def export_alerts(alerts, output_path) -> None:
    """Write alerts as JSON, representing UTC datetimes as ISO 8601 strings."""
    serialized_alerts = []
    for alert in alerts:
        serialized_alert = alert.copy()
        serialized_alert["timestamp"] = alert["timestamp"].isoformat()
        serialized_alerts.append(serialized_alert)

    with Path(output_path).open("w", encoding="utf-8") as output_file:
        json.dump(serialized_alerts, output_file, indent=4)
        output_file.write("\n")


def positive_integer(value):
    """Convert a command-line argument to a strictly positive integer."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
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

    if args.output is not None and args.output.resolve() == log_path.resolve():
        parser.error("--output must be different from the input log file")

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
        result = detect_brute_force(login_records, args.threshold, args.window)
    except ValueError as error:
        parser.exit(1, f"Error: invalid login data: {error}\n")

    if args.output is not None:
        try:
            export_alerts(result["alerts"], args.output)
        except (OSError, UnicodeError) as error:
            parser.exit(1, f"Error: could not write alerts: {error}\n")

    print("Brute-Force Login Detector ready.")
    print(f"Total failed attempts: {result['total_failures']}")
    print(f"Total alerts: {len(result['alerts'])}")

    for source_ip, timestamps in sorted(result["failures_by_ip"].items()):
        count = len(timestamps)
        print(
            f"Source IP: {source_ip}, "
            f"Failures in window at latest failure: {count}"
        )

    for alert in result["alerts"]:
        print(
            f"[ALERT] Possible brute-force activity: "
            f"Source IP: {alert['source_ip']}, Count: {alert['count']}, "
            f"Window: {alert['window_seconds']} seconds, "
            f"Time: {alert['timestamp'].isoformat()}"
        )

    if args.output is not None:
        print(f"Alerts written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
