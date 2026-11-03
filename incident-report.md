# SOC Incident Investigation Report
## Multiple Failed Logins Followed by Successful Login

**Project:** Home SOC Lab  
**SIEM:** Splunk Enterprise 10.6.1.1  
**Log Source:** Windows Security Event Logs  
**Hostname:** Mikey  
**Investigation Date:** November 3, 2026  
**Incident Type:** Authentication Failure Followed by Success  
**Environment:** Controlled lab testing

---

## 1. Incident Summary

A Splunk detection identified multiple failed Windows authentication attempts followed by a successful login for the same account.

The investigation identified four consecutive failed login attempts followed by successful authentication. The activity was generated intentionally in a controlled Windows SOC lab to test authentication monitoring and detection capabilities.

**Key findings:**

- Account: `Mikey`
- Source IP: `127.0.0.1`
- Failed authentication event: Windows Event ID `4625`
- Successful authentication event: Windows Event ID `4624`
- Logon Type: `2` — Interactive
- Failed attempts: 4 in the confirmed sequences
- Successful authentication followed the failures within approximately 22 seconds in the two confirmed four-failure sequences.

This activity was generated locally for testing. It is not evidence of an external attack.

## 2. Detection Rule

**Detection Name:** Windows - Multiple Failed Logins Followed by Success

**Detection logic:**

- Monitor Windows Security authentication events.
- Identify Event ID 4625 (failed login).
- Count failed attempts within a rolling five-minute window.
- Detect Event ID 4624 (successful login) when at least three failures occurred within that window.
- Group events by username and source IP.

### SPL Detection Query

```spl
index=main sourcetype="XmlWinEventLog:Security"
| rex "<EventID>(?<EventCode>\d+)</EventID>"
| rex "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex "<Data Name='IpAddress'>(?<SourceIP>[^<]*)</Data>"
| search EventCode=4625 OR EventCode=4624
| sort 0 _time
| streamstats time_window=5m count(eval(EventCode="4625")) as Failed_Logins by TargetUserName SourceIP
| where EventCode="4624" AND Failed_Logins>=3
| table _time TargetUserName SourceIP Failed_Logins
| sort 0 _time
```

## 3. Alert Configuration

| Setting | Configuration |
|---|---|
| Alert name | Windows - Multiple Failed Logins Followed by Success |
| Schedule | Every 5 minutes |
| Cron expression | `*/5 * * * *` |
| Search time range | Last 15 minutes |
| Trigger condition | Number of Results greater than 0 |
| Trigger action | Add to Triggered Alerts |

The alert successfully appeared in Splunk Triggered Alerts.

## 4. Event Timeline

### Confirmed four-failure sequences

| Date | Event | Time (UTC) |
|---|---|---|
| Nov 2, 2026 | Failed login (4625) | 12:37:45 |
| Nov 2, 2026 | Failed login (4625) | 12:37:47 |
| Nov 2, 2026 | Failed login (4625) | 12:37:50 |
| Nov 2, 2026 | Failed login (4625) | 12:37:53 |
| Nov 2, 2026 | Successful login (4624) | 12:38:15 |
| Nov 3, 2026 | Failed login (4625) | 04:59:52 |
| Nov 3, 2026 | Failed login (4625) | 04:59:54 |
| Nov 3, 2026 | Failed login (4625) | 04:59:57 |
| Nov 3, 2026 | Failed login (4625) | 05:00:01 |
| Nov 3, 2026 | Successful login (4624) | 05:00:24 |

The successful login followed the last failed attempt by approximately 21.88 seconds on November 2 and 22.70 seconds on November 3.

Duplicate successful event records were observed at identical timestamps. They should not automatically be interpreted as separate human logins.

## 5. Authentication Evidence

### Failed Login Analysis

Windows Event ID `4625` represents a failed logon attempt.

Observed fields:

| Field | Observed value |
|---|---|
| Target account | Mikey |
| Logon Type | 2 |
| Source IP | 127.0.0.1 |
| Status | `0xc000006d` |
| SubStatus | `0xc000006a` |

**Interpretation:**

- `0xc000006d`: Logon failure due to invalid credentials.
- `0xc000006a`: Incorrect password.

These values are consistent with the intentionally generated incorrect-password attempts in the lab.

### Successful Login Analysis

Windows Event ID `4624` represents a successful logon.

| Field | Observed value |
|---|---|
| Account | Mikey |
| Logon Type | 2 |
| Source IP | 127.0.0.1 |

Logon Type 2 indicates an interactive login.

### SYSTEM Account Analysis

The investigation also identified 104 successful logon events for the SYSTEM account.

| Account | Logon Type | Count |
|---|---|---:|
| SYSTEM | 5 — Service | 104 |

These events represent service logons, not necessarily individual user logins.

## 6. Investigation Findings

1. Multiple failed authentication attempts were recorded for the Mikey account.
2. The failed attempts were followed by successful authentication.
3. The source IP was `127.0.0.1`, indicating local loopback activity.
4. The failed authentication status values were consistent with incorrect-password attempts.
5. The successful logins used interactive Logon Type 2.
6. The SYSTEM account generated service Logon Type 5 events.
7. The Splunk scheduled detection successfully generated triggered alerts.

## 7. False Positive and Limitations

- The observed activity was intentionally generated for controlled lab testing.
- A successful login after failed attempts does not automatically prove malicious activity.
- The loopback address indicates local activity and does not identify a remote attacker.
- Duplicate Windows event records may affect event counts.
- The detection uses a rolling five-minute window and may produce repeated alerts for the same activity.
- Additional investigation is required before classifying similar activity in a production environment as malicious.

## 8. Recommended SOC Response

For a real production alert, an L1 SOC analyst should:

1. Validate the username and source IP.
2. Review the failed and successful authentication timestamps.
3. Check whether the login activity is expected.
4. Investigate related Windows Security events.
5. Check for unusual account activity or privilege changes.
6. Escalate suspicious or unexplained activity to the L2 SOC team.
7. Document the investigation and update the incident ticket.

Do not automatically disable an account or reset its password solely because this detection triggered. Follow the organization's incident response procedure.

## 9. Tools and Technologies

- Splunk Enterprise 10.6.1.1
- Splunk Universal Forwarder
- Windows Security Event Logs
- Ubuntu Server 24.04.5 LTS
- Windows SOC Virtual Machine
- VMware Workstation
- Search Processing Language (SPL)

## 10. Conclusion

This investigation demonstrates how Splunk can collect Windows Security events, identify repeated authentication failures, correlate failed logins with subsequent successful authentication, and generate scheduled alerts.

The home SOC lab successfully demonstrated log ingestion, SPL-based detection, alert configuration, dashboard visualization, and basic incident investigation.

**Project Status:** Detection and investigation successfully tested in a controlled lab environment.