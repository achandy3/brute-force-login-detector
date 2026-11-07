# SOC investigation case study: suspicious authentication activity

- **Case reference:** BF-2026-11-04-01 — fictional portfolio exercise
- **Report date:** 2026-11-06
- **Event window:** 2026-11-04, 14:00:00–14:02:00 UTC
- **Disposition:** Suspicious authentication activity; account compromise unconfirmed
- **Response status:** Recommendations only; no containment or account changes performed

## Executive summary

Analysis of nine fictional authentication records identified seven failed logins
targeting `alex` and `jordan` from `192.0.2.10`. The detector grouped the failures
into two incidents and emitted one alert under a 300-second notification cooldown.
The complete incident report retains both groups, including the group whose
notification was suppressed. [Evidence E1–E4](#evidence-and-scope)

`INC-0001` contains four failures and a subsequent successful login by `alex` from
the same IP. It receives **high** severity under the project's correlation rule.
`INC-0002` contains three failures and no correlated success in the supplied data;
it receives **medium** severity. [E3: incident summaries](evidence/investigation-incidents.json)

The sequence is consistent with possible credential guessing and warrants
investigation. A successful authentication record does not establish that an
attacker authenticated. The dataset cannot confirm malicious intent, unauthorized
access, or account compromise.

## Evidence and scope

All records, accounts, and addresses are fictional. Findings below are limited to
the supplied dataset and reproducible tool output.

| Reference | Artifact | Role |
| --- | --- | --- |
| E1 | [Source authentication records](../examples/investigation_logs.json) | Nine input events; the complete source for the timeline and account counts |
| E2 | [Captured alert JSON](evidence/investigation-alerts.json) | The single emitted notification and its final investigation context |
| E3 | [Captured incident JSON](evidence/investigation-incidents.json) | Both grouped incidents, severity reasons, correlation, and suppression counts |
| E4 | [Captured console output](evidence/investigation-console.txt) | Actual command output and run totals |
| E5 | [Execution manifest](evidence/investigation-manifest.json) | Exact command, Python version, configuration, exit status, and SHA-256 hashes |

The manifest records hashes of the source data, detector, and captured outputs.
They support checking this exercise's reproducibility and file consistency; they
do not establish the authenticity or completeness of real-world telemetry.
The capture used Python 3.15.2 and completed with exit status `0`. [E5](evidence/investigation-manifest.json)

The input contains only timestamp, username, source IP, and success status. It
provides no authentication provider, device identity, MFA outcome, session ID,
password-attempt details, geolocation, or post-login activity. These absent fields
limit attribution and any assessment of impact.

## Detection rule and configuration

| Setting | Value used for this capture |
| --- | --- |
| Detection threshold | At least 3 failures from one normalized IP |
| Rolling window | 60 seconds, including both endpoints |
| Incident continuation | Consecutive failures from the IP remain grouped while their gap is at most 60 seconds |
| New incident | A gap greater than 60 seconds, followed by another independently qualifying session |
| Notification suppression | 300 seconds from the last emitted alert for that IP; suppressed events do not extend it |
| Investigation mode | Enabled; both alerts and complete incidents exported |
| Successful-login correlation | Same IP and a previously targeted account, strictly after detection and within 60 seconds of that account's most recent earlier failure |
| Severity | Medium after threshold breach; high for a correlated success or a peak rolling count of at least 6 (`2 × threshold`) |

Configuration comes from [E5](evidence/investigation-manifest.json); exact grouping
and correlation behavior is defined in the
[investigation policy](investigation-context.md).

## Event timeline

All timestamps below are on **2026-11-04 in UTC**. `R01`–`R09` are analyst-assigned
references to source-array positions 1–9 in [E1](../examples/investigation_logs.json),
not native event IDs or JSON line numbers. Interpretations are checked against
[E2](evidence/investigation-alerts.json) and [E3](evidence/investigation-incidents.json).

| Record | Time (UTC) | Source IP | Account | Outcome | Detection or investigation significance |
| --- | --- | --- | --- | --- | --- |
| R01 | 14:00:00 | 192.0.2.10 | alex | Failure | First failure in the first qualifying window |
| R02 | 14:00:10 | 192.0.2.10 | jordan | Failure | Rolling failure count reaches 2 |
| R03 | 14:00:20 | 192.0.2.10 | alex | Failure | Count reaches 3; INC-0001 is detected and the alert is timestamped here |
| R04 | 14:00:25 | 192.0.2.30 | alex | Success | Different source IP; excluded from this incident's success correlation |
| R05 | 14:00:30 | 192.0.2.10 | jordan | Failure | Count reaches 4; notification suppressed 10 seconds after the emitted alert |
| R06 | 14:00:35 | 192.0.2.10 | alex | Success | Correlates with alex's failure at 14:00:20, 15 seconds earlier and after detection |
| R07 | 14:01:40 | 192.0.2.10 | alex | Failure | A 70-second gap since the preceding failure begins a separate session |
| R08 | 14:01:50 | 192.0.2.10 | alex | Failure | The new session's rolling failure count reaches 2 |
| R09 | 14:02:00 | 192.0.2.10 | jordan | Failure | Count reaches 3; INC-0002 is detected, but its notification remains suppressed |

The first alert's timestamp remains `14:00:20`. Its high severity incorporates the
success at `14:00:35` during final batch enrichment. The output does not show that
the detector knew about the success at the earlier alert time. [E2](evidence/investigation-alerts.json)

## Affected accounts and sources

Here, “affected” means targeted by recorded failed logins, not confirmed compromised.
Counts are calculated directly from [E1](../examples/investigation_logs.json).

| Account | Failed logins | Successful logins | Observed scope |
| --- | --- | --- | --- |
| alex | 4 | 2 | Targeted in both groups; one success from each source IP; only the 14:00:35 success correlates |
| jordan | 3 | 0 | Targeted in both groups; no successful login recorded in this dataset |

| Source IP | Failed logins | Successful logins | Interpretation |
| --- | --- | --- | --- |
| 192.0.2.10 | 7 | 1 | Source of both incidents and the correlated success |
| 192.0.2.30 | 0 | 1 | Does not meet the failure rule; its single success is not enough to classify the source as benign or malicious |

## Detection evidence and severity assessment

These values are copied from [E3](evidence/investigation-incidents.json):

| Incident | Failure interval (UTC) | Failures | Peak rolling count | Correlated success | Severity | Emitted / suppressed notifications |
| --- | --- | --- | --- | --- | --- | --- |
| INC-0001 | 14:00:00–14:00:30 | 4 | 4 | Yes | high | 1 / 1 |
| INC-0002 | 14:01:40–14:02:00 | 3 | 3 | No | medium | 0 / 1 |

| Finding | Supporting evidence | Assessment |
| --- | --- | --- |
| A failure threshold was breached at 14:00:20 | R01–R03; E2 `count=3`, `timestamp=2026-11-04T14:00:20+00:00` | Three failures occurred within 20 seconds, inside the 60-second rule |
| The first incident merits higher review priority | R06; E3 INC-0001 `successful_login_after_failures=true` and its `successful_logins` entry | The high rating comes from the correlated success, not the volume condition: peak 4 is below 6 |
| A separate suspicious group was retained without an emitted alert | R07–R09; E3 INC-0002 `failure_count=3`, `alert_count=0`, `suppressed_alert_count=1` | The second threshold breach is 100 seconds after the last emitted alert, inside the 300-second cooldown |
| Notification totals understate the number of grouped incidents | E4 reports 1 alert and 2 incidents; E3 totals 2 suppressed notifications | Investigation should review the complete incident report, not just the alert list |

INC-0002 remains medium because its peak is below 6 and no qualifying success
appears in the provided events. The input ends at its detection timestamp,
`14:02:00`; this is not evidence that no success occurred afterward.

## Analyst assessment

**Observed:** Repeated authentication failures from one source target two
accounts, independently meet the rule in two sessions, and precede one correlated
successful login. These observations are supported by E1–E3.

**Assessment:** The pattern is suspicious and consistent with possible credential
guessing or brute-force-like activity. The available fields do not distinguish
password guessing, password spraying, credential reuse, legitimate retries, or
stale automated credentials. Malicious intent and the identity of the person or
process authenticating remain undetermined.

**Not established:** Unauthorized access, stolen credentials, MFA bypass,
persistence, lateral movement, or data access. No endpoint, session, or post-login
evidence was provided. The working disposition is **suspicious activity requiring
validation; compromise unconfirmed**.

## Recommended response actions

These are proposed actions for an authorized SOC handling a comparable real
case. None were performed in this fictional exercise.

| Priority | Recommended action | Rationale and evidence |
| --- | --- | --- |
| First | Preserve provider authentication records and request a broader timeline for both accounts and source IPs, including MFA, device, and session details | E1 lacks the fields needed to validate identity, access, and impact |
| First | Validate alex's 14:00:35 sign-in through trusted account-owner and identity-provider procedures; review the other success at 14:00:25 as well | R04 and R06 show successful authentication, but not who authenticated or whether it was authorized |
| Conditional containment | If the success is determined to be unauthorized, or other evidence establishes active account risk, follow the organization's approval and response playbook to restrict access, revoke sessions, and reset affected credentials | R06 justifies investigation and possible escalation, not automatic account-compromise attribution |
| Conditional containment | Verify the real source's ownership and shared-network use before rate limiting or temporary blocking | Source-based grouping can combine unrelated users behind a shared IP; the exercise's documentation addresses are not operational block targets |
| Follow-up | Review MFA enforcement, authentication throttling, lockout behavior, and stale automated credentials against the environment's baseline | These controls and benign explanations cannot be assessed from the four-field dataset |
| Detection review | Review all incident summaries and evaluate a separate new-incident or severity-escalation notification policy | INC-0002 has no emitted alert; the current tool preserves evidence but does not notify on severity changes or bypass the per-IP cooldown for new groups |

## Limitations and possible false positives

- Nine synthetic records demonstrate a rule, not its real-world detection rate,
  accuracy, or an operational deployment.
- User mistakes, shared egress addresses, and applications using stale credentials
  could produce a similar pattern. No baseline or user verification is available
  to accept or reject those explanations.
- A successful login after failures can be legitimate. Its correlation is based
  on matching account, source, and timing, not evidence of attacker control.
- The capture has no events after 14:02:00, limiting follow-up on INC-0002.
- Per-IP grouping can miss distributed or slower attempts. The schema has no
  tenant or domain identifiers, and duplicate records are counted as separate
  attempts.
- Reports are finalized after the batch. Later evidence enriches earlier
  notifications, and a long cooldown can hide a separate group from the alert
  list. Incident IDs are local to this run.

## Reproduce and review

From the repository root, regenerate equivalent reports without overwriting the
captured documentation evidence:

```bash
mkdir -p reports
python3 -B detector.py examples/investigation_logs.json \
  --threshold 3 --window 60 --suppression-seconds 300 --investigate \
  --output reports/case-study-alerts.json \
  --incidents-output reports/case-study-incidents.json
```

The JSON findings should match E2 and E3. Console destination paths differ because
this command writes into `reports/`. E5 records the original capture command and
hashes for an exact replay. No external system access is needed.

[Back to the project overview](../README.md)
