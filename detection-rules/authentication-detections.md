# Windows Authentication Detection Rules

## 1. Failed Login Monitoring

**Event ID:** 4625  
**Purpose:** Identify failed Windows authentication attempts.

```spl
index=main sourcetype="XmlWinEventLog:Security"
| rex "<EventID>(?<EventCode>\d+)</EventID>"
| rex "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex "<Data Name='IpAddress'>(?<SourceIP>[^<]*)</Data>"
| search EventCode=4625
| table _time TargetUserName SourceIP EventCode
| sort -_time
```

## 2. Successful Login Monitoring

**Event ID:** 4624  
**Purpose:** Monitor successful Windows authentication events.

```spl
index=main sourcetype="XmlWinEventLog:Security"
| rex "<EventID>(?<EventCode>\d+)</EventID>"
| rex "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex "<Data Name='LogonType'>(?<LogonType>[^<]*)</Data>"
| rex "<Data Name='IpAddress'>(?<SourceIP>[^<]*)</Data>"
| search EventCode=4624 TargetUserName="Mikey"
| table _time TargetUserName LogonType SourceIP
| sort -_time
```

## 3. Multiple Failed Logins Followed by Success

**Detection:** At least three failed logins followed by a successful login within a rolling five-minute window.

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

## Event Reference

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |

## Testing Results

The detection rules were tested in a controlled Windows SOC lab environment using the account `Mikey`.

The correlation detection successfully identified multiple failed authentication attempts followed by successful authentication.

**Note:** The observed source IP was `127.0.0.1` (local loopback). The test activity was intentionally generated for educational purposes.
