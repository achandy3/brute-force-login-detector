# Incident grouping and investigation context

Investigation mode adds batch investigation context to the existing rolling-window
detector. Enable it with `--investigate` or `investigate=True` in the Python API.
Without that option, the original return structure, JSON alert fields, alert
counts, and suppression policy remain unchanged.

## Grouping policy

An incident is a grouped set of suspicious authentication observations, not a
confirmed security breach or a formally closed SOC case.

1. Records are validated, sorted by event time, and grouped by normalized source
   IP. Different usernames from one IP can belong to the same incident.
2. A new incident is created only when an IP meets the configured rolling-window
   failure threshold. Its initial evidence is all failures in that first
   qualifying window, including the triggering failure. Older failures outside
   that window are excluded from the incident and remain in the overall total.
3. Later failures from the IP join the incident while the gap from its preceding
   failure is **at most `window_seconds`**. They join even if the current rolling
   count falls below the threshold. This keeps a continuing session together.
4. A gap **greater than `window_seconds`** ends the preceding group. A later
   session becomes another reported incident only if it independently reaches
   the rolling-window threshold. Successful logins do not extend this gap.
5. Each incident receives an ID such as `INC-0001`. IDs identify groups within one
   analysis run; they are not persistent identifiers across files or reruns.

The detection window and grouping gap use the same configured duration to keep
the policy small and reproducible. A continuing group can span longer than one
window; its total failure count is therefore distinct from its peak rolling
count. End-of-file finalizes the available summary, not an investigative outcome.

## Counts and timestamps

| Field | Meaning |
| --- | --- |
| Alert `count` | Original rolling count at that notification's triggering event |
| Alert `timestamp` | Original time of that triggering failure |
| Alert `incident_failure_count` | Total failures assigned to the incident across the complete input |
| Incident `failure_count` | The same complete incident total |
| `peak_window_count` | Largest rolling count reached within that incident |
| `affected_usernames` | Sorted unique account names that failed within the incident |
| `first_failure`, `last_failure` | Earliest and latest failures assigned to the incident |
| `first_detected` | Failure time at which the rolling threshold was first reached |
| Incident `alert_count` | Number of emitted notifications assigned to the incident |
| Incident `suppressed_alert_count` | Number of qualifying failure events whose notifications were suppressed |

All output times use UTC. Account strings are matched exactly as supplied; the
data model has no domain, tenant, device, or user-identity resolution.

The four original alert fields (`source_ip`, `count`, `window_seconds`, and
`timestamp`) keep their original meanings. Investigation fields describe the
**final batch summary**, so they can include failures and successes later than an
alert's trigger timestamp. They must not be interpreted as knowledge available at
the moment that alert would have fired in a streaming system.

## Successful-login correlation

`successful_login_after_failures` is true only when a successful record:

- Uses the same normalized IP as the incident.
- Targets an account that already had a failed login assigned to that incident.
- Occurs strictly after `first_detected`.
- Occurs strictly after a prior failure of that account and no more than
  `window_seconds` after that account's most recent earlier failure in the group.

Every matching success is preserved in `successful_logins` with its username and
timestamp. A success from another IP, for an unrelated account, before detection,
or outside the correlation interval does not match. A failure that happens later
cannot retroactively make a preceding success relevant.

At equal timestamps, the context builder evaluates successes before failures at
that instant, using only strictly earlier evidence. This makes correlation
independent of the original ordering of tied rows. A success exactly at the first
detection timestamp is not classified as occurring after detection.

A match helps an analyst prioritize reviewing the session, user identity, MFA
events, and endpoint evidence. It does not establish who authenticated or whether
the login was unauthorized. A false value means no matching success was observed
under these rules in the supplied data; it does not establish absence of account
compromise.

## Severity rules

These are transparent demonstration rules for triage, rather than a standardized
or environment-tuned risk score.

| Severity | Rule |
| --- | --- |
| `medium` | The incident met the failure threshold, with neither high-severity condition below |
| `high` | A correlated successful login was observed, **or** `peak_window_count >= 2 * failure_threshold` |

`severity_reasons` lists the applicable evidence. Cumulative failures across a
long incident alone do not satisfy the volume rule: the peak rolling-window
count must reach twice the configured threshold. Every emitted alert linked to
an incident receives that incident's final batch severity. No `critical` severity
or finding of confirmed compromise is inferred.

## Interaction with suppression

Suppression continues to control notifications using the last emitted alert time
for each IP. Grouping and evidence collection run independently:

- Suppressed failures still extend an active incident and contribute to its
  counts, affected accounts, timing, peak count, and severity.
- A later successful login can add context even when subsequent alerts were
  suppressed. It does not generate another notification or reset the cooldown.
- A separate incident from the same IP can start during a long cooldown. That
  incident is retained even if every qualifying notification for it is suppressed.
- With suppression disabled, repeated notifications retain their original
  behavior and link to the same incident while that group continues.

Use `--incidents-output` to export all groups, including those without emitted
alerts. `--output` remains the notification list, so it cannot represent a group
whose notifications were all suppressed. A streaming system would need a
separate escalation/update policy if changed incident severity should notify an
analyst immediately; this batch project does not implement that workflow.

## Reproduce a fictional investigation

```bash
mkdir -p reports
python3 detector.py examples/investigation_logs.json --investigate --suppression-seconds 300 --output reports/alerts.json --incidents-output reports/incidents.json
```

With the default threshold of three and 60-second window, this input contains:

- Seven failed attempts across two sessions from `192.0.2.10`.
- A successful login by `alex` from that source after the first threshold breach.
- An unrelated success from `192.0.2.30`, which does not correlate.

The first group has four failures and high severity because of the correlated
success. The second has three failures and medium severity. Only one alert is
emitted: the 300-second cooldown suppresses one additional notification in the
first incident and all notifications in the second. Both incidents appear in the
incident report.

The fictional accounts and documentation-range addresses model evidence handling
for practice. The input is not evidence of a real attack or deployed detection.
