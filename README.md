# Brute-Force Login Detector

A defensive Python portfolio project that analyzes fictional authentication
records and flags repeated failed logins from the same source IP within a
configurable rolling time window.

The project demonstrates structured log processing, input validation, event-time
analysis, command-line tools, JSON reporting, and automated testing. All included
accounts and records are fictional; example IPs use documentation ranges.

## Requirements

- Python 3.10 or newer.
- Standard library only; no package installation is required.

Run commands from the project folder unless you provide absolute paths.

## Quick start

```bash
python3 --version
python3 detector.py
python3 -m unittest -v
```

The default sample contains five login attempts, including four failures. Its
failures are spread across sources and time, so the default rule produces no
alerts:

```text
Brute-Force Login Detector ready.
Total failed attempts: 4
Total alerts: 0
Source IP: 192.0.2.10, Failures in window at latest failure: 1
Source IP: 192.0.2.30, Failures in window at latest failure: 1
```

Try the burst example and export its alert:

```bash
python3 detector.py examples/burst_logs.json --threshold 3 --window 60 --output alerts.json
```

This produces four total failures and one alert for `192.0.2.10` at
`2026-11-04T14:00:40+00:00`. The alert contains three failures within 60 seconds.

## Command-line options

```text
python3 detector.py [log_file] [--threshold N] [--window SECONDS] [--output PATH]
```

| Argument | Purpose | Default |
| --- | --- | --- |
| `log_file` | UTF-8 JSON input file | `sample_logs.json` beside the script |
| `--threshold` | Minimum failed attempts from one IP for an alert | `3` |
| `--window` | Rolling window length in seconds | `60` |
| `--output` | Write alerts to a JSON file | Console output only |
| `--help` | Show usage information | — |

Threshold and window values must be positive integers. Explicit relative input
and output paths are resolved from the current working directory. The default
input path works even if the script is launched from another directory.

The output file's parent directory must exist. An existing output file is
overwritten; the input log path cannot also be used as the output path. With no
alerts, an exported report contains `[]`.

Exit statuses:

- `0`: analysis and any requested export succeeded, whether or not alerts exist.
- `1`: input could not be read or validated, or the report could not be written.
- `2`: command-line usage error, including invalid threshold or window arguments.

## Input format

The input must be a JSON array of objects:

```json
[
    {
        "timestamp": "2026-11-04T14:00:00+00:00",
        "username": "alex",
        "source_ip": "192.0.2.10",
        "success": false
    }
]
```

| Field | Requirement |
| --- | --- |
| `timestamp` | Nonempty ISO 8601 date/time string with an explicit timezone offset |
| `username` | Nonempty string |
| `source_ip` | Valid IPv4 or IPv6 address string |
| `success` | JSON Boolean: `true` or `false` |

JSON Boolean values must not be quoted. For example, `"false"` is a string and
will be rejected. No password field is required. Additional fields are ignored.
All records, including successful attempts, are validated before detection.
One invalid record stops the run with a record-specific error.

## Detection behavior

1. Validate the configuration and all input records.
2. Sort records by the instant represented by their timestamps.
3. Convert failure timestamps to UTC and normalize source IP representations.
4. Keep a queue of failed-attempt times for each source IP.
5. At a failure occurring at time `t`, discard failures older than `t - window`.
6. Emit an alert whenever the retained count is at least the threshold.

Both endpoints of the interval `[t - window, t]` are included. With a 60-second
window, an attempt exactly 60 seconds old still counts; one 61 seconds old does
not. Duplicate records are treated as separate attempts, so input should not
contain accidental duplicate events.

Failures across different usernames from the same IP share one history.
Successful logins do not count toward the threshold and do not reset failures.
Equivalent IPv6 spellings share a normalized IP key. IPv4 and IPv4-mapped IPv6
addresses remain separate representations.

Every qualifying failed attempt emits an alert. For four failures in one window
and a threshold of three, the detector emits alerts with counts of three and
four. It does not suppress repeated alerts.

The final per-IP counts describe windows ending at **each IP's latest failure**.
They are not counts for one common window ending at the end of the file. The
total failure count includes failures that have expired from those queues.

## Alert format

Exported reports are JSON arrays. Timestamps are ISO 8601 strings in UTC:

```json
[
    {
        "source_ip": "192.0.2.10",
        "count": 3,
        "window_seconds": 60,
        "timestamp": "2026-11-04T14:00:40+00:00"
    }
]
```

`timestamp` is the event time of the failed login that triggered the alert.
The detector's Python return value uses timezone-aware `datetime` objects;
`export_alerts()` converts those into strings for JSON without modifying them.

## Tests

```bash
python3 -m unittest -v
```

The suite covers thresholds, expiration, exact boundaries, separate IPs,
multiple accounts, successful logins, unordered records, timezone offsets,
equivalent IPv6 addresses, empty input, invalid records and configuration,
command-line behavior, JSON exports, and file errors. Command-line tests use
temporary files and run the script from another directory.

## Project files

```text
brute-force-login-detector/
├── detector.py               # Validation, detection, reporting, and CLI
├── test_detector.py          # Unit and command-line tests
├── sample_logs.json          # Fictional example with no default-rule alert
├── examples/
│   └── burst_logs.json       # Fictional example that triggers an alert
├── README.md
└── .gitignore
```

Generated `alerts.json`, files under `reports/`, Python caches, and local virtual
environments are excluded from Git. Sample records and tests are tracked source
files once added to a commit.

## Scope and limitations

- Alerts indicate a pattern worth investigating; they do not prove an attack.
  Shared networks and ordinary login mistakes can produce false positives.
- This rule groups activity by source IP. Distributed attempts and attempts
  spread beyond the configured window may not trigger it.
- This is a batch analyzer. It loads the input file, sorts records in memory,
  and retains generated alerts. It is intended for small simulated datasets,
  rather than continuous monitoring or very large log files.
- The default threshold and window are demonstration settings. An operational
  rule would need tuning against the environment's normal authentication data.
- The tool reports findings; it does not contact hosts, block IPs, or change
  accounts.
