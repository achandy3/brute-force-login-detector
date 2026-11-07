# Brute-Force Login Detector

[![Python tests](https://github.com/achandy3/brute-force-login-detector/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/achandy3/brute-force-login-detector/actions/workflows/tests.yml)

A defensive Python portfolio project that analyzes fictional authentication logs,
detects repeated failed logins within a configurable time window, and produces
alerts with optional SOC investigation context.

**Start with the [fictional SOC investigation case study](docs/investigation-case-study.md):**
it traces seven failures across two accounts, explains a related successful login,
and shows why two incidents can produce only one notification. Every finding links
to source records or captured detector output.

## Project overview

This project demonstrates authentication-log triage, event correlation, alert
suppression, incident scoping, evidence-based reporting, and automated testing.
It models parts of a SOC analyst's workflow using small simulated datasets.

Features:

- Per-IP rolling-window detection with configurable thresholds and inclusive time boundaries.
- Optional alert suppression that reduces repeat notifications without changing rolling-window detection.
- Incident grouping with affected accounts, first/last failures, and peak rolling counts.
- Bounded correlation of successful logins after suspicious failures.
- Documented medium/high severity rules and JSON alert/incident reports.
- Input validation, UTC conversion, IPv4/IPv6 normalization, and unordered-log support.
- Standard-library unit and CLI tests, plus a GitHub Actions Python-version matrix.

The case study shows how these outputs can help an analyst build a timeline,
identify accounts to investigate, and prioritize follow-up. The report separates
recorded facts, analyst assessment, and proposed response actions. No real-world
deployment, confirmed attack, or detection-accuracy claim is made.

## Installation

Requirements: **Python 3.10 or newer** and Git to clone the repository. The detector
and tests use only the Python standard library; no package installation is needed.

```bash
git clone https://github.com/achandy3/brute-force-login-detector.git
cd brute-force-login-detector
python3 --version
```

The existing Python 3.10 compatibility minimum remains unchanged. CI is configured
for maintained CPython versions **3.11–3.15**. Python 3.10 reached upstream end of
life in October 2026 and is excluded from that matrix; see the
[Python version support table](https://devguide.python.org/versions/).

## Usage

Run commands from the project root unless you use absolute paths.

### Basic detection

```bash
python3 detector.py
python3 detector.py examples/burst_logs.json --threshold 3 --window 60
```

The default `sample_logs.json` contains four failures and produces no alert under
the default rule. The burst example produces one alert for `192.0.2.10` after
three failures within 60 seconds.

### Compare alert suppression

```bash
python3 detector.py examples/repeated_failures.json
python3 detector.py examples/repeated_failures.json --suppression-seconds 60
```

Both runs count five failures. The default emits three notifications; a 60-second
cooldown emits one. Set `--suppression-seconds 0` to preserve the original behavior.

### Reproduce the investigation

```bash
mkdir -p reports
python3 -B detector.py examples/investigation_logs.json \
  --threshold 3 --window 60 --suppression-seconds 300 --investigate \
  --output reports/alerts.json --incidents-output reports/incidents.json
```

Selected lines from the [captured run](docs/evidence/investigation-console.txt):

```text
Total failed attempts: 7
Total alerts: 1
Total incidents: 2
```

Incident summary from the [saved JSON report](docs/evidence/investigation-incidents.json):

| Incident | Failures | Peak count | Related success | Severity | Alerts / suppressed |
| --- | --- | --- | --- | --- | --- |
| INC-0001 | 4 | 4 | Yes | high | 1 / 1 |
| INC-0002 | 3 | 3 | No | medium | 0 / 1 |

The first incident includes a correlated success by `alex`; the second has no
correlated success in the supplied events. The cooldown suppresses the second
incident's notification, but its evidence remains in the full incident report.
See the [case study](docs/investigation-case-study.md) for the timeline, evidence,
severity assessment, limitations, and conditional response recommendations.

### Command-line options

Use `python3 detector.py --help` for the complete usage description.

| Argument | Purpose | Default |
| --- | --- | --- |
| `log_file` | UTF-8 JSON input file | `sample_logs.json` beside the script |
| `--threshold` | Minimum failures from one source IP needed for an alert | `3` |
| `--window` | Rolling window and incident continuation gap, in seconds | `60` |
| `--suppression-seconds` | Minimum interval between emitted alerts from one IP; `0` disables it | `0` |
| `--investigate` | Add incidents, affected accounts, related successes, and severity | Disabled |
| `--output` | Export the emitted notification list as JSON | No alert file |
| `--incidents-output` | Export all incident summaries; requires `--investigate` | No incident file |

Threshold and window values must be positive integers; suppression must be a
nonnegative integer. Relative input/output paths use the current working directory.
The default input is located beside the script, so it also works from another
directory. Output directories must exist, existing reports are overwritten, and
input, alert-output, and incident-output paths must be distinct.

Exit status `0` means analysis and requested exports succeeded, including runs
that found alerts. Status `1` indicates input, validation, or export failure;
status `2` indicates incorrect command usage.

## Input format

The input is a JSON array of login objects:

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
| `timestamp` | Nonempty ISO 8601 date/time with an explicit timezone offset |
| `username` | Nonempty string; account matching is case-sensitive and exact |
| `source_ip` | Valid IPv4 or IPv6 address string |
| `success` | JSON Boolean `true` or `false`, not a quoted string |

All records are validated before analysis, including successful logins. One invalid
record stops the run with an error. Additional fields are ignored; passwords are
not required. Included accounts and logs are fictional, and sample IPs use
addresses reserved for documentation.

## Detection and investigation policy

### Rolling-window rule

Records are sorted by event time. Failure timestamps are converted to UTC and
source IPs are normalized. A separate queue per IP retains failures in the
inclusive interval `[current failure time - window, current failure time]`.

With a 60-second window, an attempt exactly 60 seconds old counts; one 61 seconds
old expires. Failures across different accounts from the same IP share a queue.
Successful logins neither count as failures nor reset failure history. Duplicate
input records count as separate events. Equivalent IPv6 spellings share a key;
IPv4 and IPv4-mapped IPv6 representations remain separate.

The total failure count includes expired failures. Final per-IP counts describe
windows ending at each IP's latest failure, rather than one common window ending
at the end of the file.

### Optional suppression

The default `0` emits an alert for every qualifying failure. With a positive
cooldown, the first qualifying failure emits an alert immediately. A later
qualifying event from that normalized IP alerts only when its timestamp is at
least the configured interval after the **last emitted alert**.

Suppressed events still count, do not extend the cooldown, and do not alter the
original count/timestamp fields of earlier notifications. A success or a rolling
count falling below the threshold does not reset suppression. The cooldown can
span separate incidents from the same IP, and is independent for other IPs.
State starts fresh for each API call or CLI run; there is no cross-file persistence.

### Incidents, success correlation, and severity

Investigation mode starts an incident at the first threshold breach, seeding it
with failures in that qualifying window. Later failures remain in that incident
while their gap from the preceding failure is at most the configured window.
A larger gap starts a new session, which must independently reach the threshold
before it becomes a reported incident. Incident IDs are local to the analysis run.

A successful login correlates only with the same IP and an account that previously
failed in the incident, strictly after detection and within the window after that
account's most recent earlier failure. Other sources, unrelated accounts, earlier
successes, and stale successes are excluded.

| Severity | Rule |
| --- | --- |
| `medium` | Failure threshold reached without a high-severity condition |
| `high` | A correlated successful login, or peak rolling count at least twice the threshold |

These are transparent triage heuristics, not findings of confirmed compromise.
The [complete policy](docs/investigation-context.md) specifies exact boundaries,
tied timestamps, exclusions, grouping, and suppression interactions.

### Reports and compatibility

`--output` exports emitted notifications. `--incidents-output` exports all grouped
incidents, including those with no emitted alert. Empty reports contain `[]`.
Investigation fields include affected accounts, first/last failures, first detection,
incident-wide totals, peak rolling counts, successful-login evidence, severity
reasons, and emitted/suppressed notification counts in incident summaries.

The original alert fields (`source_ip`, `count`, `window_seconds`, `timestamp`)
retain their meanings. `count` is the rolling count at the triggering event;
`incident_failure_count` is the full incident total. Added context describes the
completed batch and can include evidence later than the alert's timestamp.

Existing calls retain their original result keys and four-field alert schema
unless investigation mode is enabled:

```python
import json
from pathlib import Path

from detector import detect_brute_force

records = json.loads(Path("examples/investigation_logs.json").read_text(encoding="utf-8"))
result = detect_brute_force(records, investigate=True, suppression_seconds=300)
incidents = result["incidents"]
```

Python results contain timezone-aware `datetime` objects; JSON exports convert
them to ISO 8601 strings without modifying the result objects.

## Testing

Run the full suite from the project root:

```bash
python3 -B -m unittest discover --start-directory . --pattern "test_*.py" --verbose
```

The shortcut `python3 -m unittest -v` also works. Discovery includes
`test_detector.py`, `test_investigation.py`, and future matching files. Tests cover
thresholds, exact boundaries, independent IPs, successes, unordered logs, timezone
offsets, IPv6 normalization, suppression, incident separation, success correlation,
severity, input/configuration errors, CLI behavior, and JSON reports. File-based
CLI tests use temporary directories.

### GitHub Actions

[The workflow](.github/workflows/tests.yml) is configured to run the full suite on
every push and pull request. Five Ubuntu 24.04 jobs select CPython 3.11–3.15,
display their interpreter version, and run the same discovery command using `python`.
Minor-version entries select an available matching patch release.

- A failed version does not cancel the other jobs (`fail-fast: false`).
- Each job has a ten-minute timeout; failed tests are not ignored.
- Only GitHub-maintained checkout/setup actions are used, pinned to full commit hashes.
- Permissions are limited to `contents: read`; checkout does not persist credentials.
- No project dependencies, package caches, repository secrets, publishing, or deployment steps are needed.

For a failure, open **Actions → Python tests → the failed Python 3.x job → Run full
unittest suite**. Verbose output shows test names, assertions, and tracebacks; an
error annotation identifies the failed Python version. Setup failures appear in
their own named steps. Reproduce with the local command using that interpreter.

The badge reflects the latest hosted run on `main`, not local results. A GitHub
matrix result is available only after the workflow is published and runs; adding
the workflow and passing local tests does not establish a hosted CI pass.

## Project structure

```text
brute-force-login-detector/
├── .github/workflows/tests.yml      # Push and pull-request test matrix
├── detector.py                     # Validation, detection, reports, and CLI
├── test_detector.py                # Core detection, validation, and CLI tests
├── test_investigation.py           # Grouping, context, and investigation tests
├── sample_logs.json                # Example with no default-rule alert
├── examples/
│   ├── burst_logs.json              # Threshold breach
│   ├── repeated_failures.json       # Suppression comparison
│   └── investigation_logs.json      # Case-study source data
├── docs/
│   ├── investigation-case-study.md  # SOC report with linked evidence
│   ├── investigation-context.md     # Exact policy and field definitions
│   └── evidence/                    # Captured JSON, console output, and manifest
├── README.md
└── .gitignore
```

Generated `alerts.json`, reports under `reports/`, caches, and local virtual
environments are ignored by Git. The case study links its reproducible snapshot
under `docs/evidence/`, so readers can inspect evidence without regenerating it.

## Scope and limitations

- Alerts indicate suspicious patterns, not proof of attack or compromise. Shared
  networks, user mistakes, and stale automated credentials can cause false positives.
- Per-IP detection can miss distributed or slower attempts. The schema contains
  no tenant/domain identity, MFA outcome, device/session context, or post-login activity.
- Success correlation and severity are limited to the supplied events and documented
  heuristics. Missing later events cannot establish that an account remained safe.
- This batch tool loads and sorts logs in memory. It is intended for small simulated
  datasets, not continuous monitoring or very large files.
- Investigation context is finalized after the batch. Severity changes do not emit
  separate notifications, and a long cooldown may suppress an entirely new incident.
- Default values demonstrate the rule; operational thresholds would require an
  environment-specific baseline. The tool does not contact hosts or change accounts.
