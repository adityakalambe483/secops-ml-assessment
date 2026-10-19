# Security Assessment Report

**Period analysed:** 2026-09-15T00:17:44 → 2026-09-21T23:36:22  
**Events:** 12,145 · **Alerts:** 1,926 · **Incidents:** 29 · **Findings:** 45  
**Detector:** random_forest (alert threshold 0.3827)

## 1. Executive summary

| Severity | Incidents |
|---|---|
| Informational | 2 |
| Low | 7 |
| Medium | 4 |
| High | 9 |
| Critical | 7 |

**Priority incidents:**

- `INC-0003` (Critical) – Collection, Exfiltration from 10.1.0.38 → external-egress, file-01
- `INC-0004` (Critical) – Initial Access from 192.0.2.224 → ad-01
- `INC-0007` (Critical) – Reconnaissance, Initial Access, Privilege Escalation / Persistence, Exfiltration from 10.0.1.10, 203.0.113.246 → external-egress, web-01
- `INC-0013` (Critical) – Initial Access from 203.0.113.247 → vpn-gw
- `INC-0021` (Critical) – Collection, Exfiltration from 10.1.0.23 → external-egress, file-01

## 2. Detection model performance (temporal hold-out)

Model **random_forest** – precision 0.9979, recall 0.9974, F1 0.9977, PR-AUC 0.9999, FPR 0.00039. Confusion matrix: {'tn': 10216, 'fp': 4, 'fn': 5, 'tp': 1920}.

**Correlation vs ground truth:** {"ground_truth_incidents_in_data": 24, "detected_incidents": 29, "clusters_with_no_true_attack_events": 5, "mean_purity_of_clusters_containing_attacks": 1.0, "gt_incidents_recovered_in_single_cluster_pct": 100.0, "gt_incidents_split_across_clusters": 0, "gt_incidents_missed": 0}

## 3. Correlated incidents

### INC-0003 – Critical

- **Window:** 2026-09-15T23:45:03 → 2026-09-15T23:57:01 (718s)
- **Sources:** 10.1.0.38  **Assets:** external-egress, file-01
- **Kill-chain stages:** Collection → Exfiltration  **Alerts:** 119 (mean P=0.992)
- **Why it was flagged:**
  - [Bulk file access (possible data staging)] 116 file-access events by 1 user(s) from 10.1.0.38 within 3.8 min (peak 117 events in 5 min, off-hours=True).
  - [Large outbound data transfer (possible exfiltration)] 11,686 MB sent out in 3 transfer(s) from 10.1.0.38 to external-egress.
  - Multi-stage chain: Collection → Exfiltration – linked by shared source IP / pivot through compromised asset.
  - Model confidence: mean P(suspicious)=0.99, min=0.53.
- **Sample evidence:**
  - #1832 2026-09-15T23:45:35 10.1.0.38 → file-01:445 file_access user=user38 status=success P=1.00
  - #1875 2026-09-15T23:47:01 10.1.0.38 → file-01:445 file_access user=user38 status=success P=1.00
  - #1917 2026-09-15T23:48:25 10.1.0.38 → file-01:445 file_access user=user38 status=success P=1.00
  - #1919 2026-09-15T23:48:29 10.1.0.38 → file-01:445 file_access user=user38 status=success P=1.00
  - #1921 2026-09-15T23:48:33 10.1.0.38 → file-01:445 file_access user=user38 status=success P=1.00

### INC-0004 – Critical

- **Window:** 2026-09-16T00:41:58 → 2026-09-16T00:45:54 (236s)
- **Sources:** 192.0.2.224  **Assets:** ad-01
- **Kill-chain stages:** Initial Access  **Alerts:** 73 (mean P=0.9897)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 72 failed logins from 192.0.2.224 against ad-01 within 3.5 min (35 distinct account(s)); peak 72 failures in a 5-min window.
  - [Successful login following hostile activity (probable credential compromise)] successful login for 'user39' from 192.0.2.224 after hostile activity from the same source.
  - Model confidence: mean P(suspicious)=0.99, min=0.90.
  - Threat intel: 192.0.2.224 listed as scanner (confidence 93, synthetic-demo-feed)
- **Sample evidence:**
  - #1976 2026-09-16T00:43:46 192.0.2.224 → ad-01:389 login_failed user=user33 status=failure P=0.99
  - #1984 2026-09-16T00:44:10 192.0.2.224 → ad-01:389 login_failed user=user37 status=failure P=0.99
  - #1988 2026-09-16T00:44:22 192.0.2.224 → ad-01:389 login_failed user=user35 status=failure P=0.99
  - #1989 2026-09-16T00:44:25 192.0.2.224 → ad-01:389 login_failed user=user12 status=failure P=0.99
  - #1990 2026-09-16T00:44:28 192.0.2.224 → ad-01:389 login_failed user=user06 status=failure P=0.99

### INC-0007 – Critical

- **Window:** 2026-09-17T01:36:49 → 2026-09-17T02:21:15 (2666s)
- **Sources:** 10.0.1.10, 203.0.113.246  **Assets:** external-egress, web-01
- **Kill-chain stages:** Reconnaissance → Initial Access → Privilege Escalation / Persistence → Exfiltration  **Alerts:** 73 (mean P=0.9909)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 40 blocked/scan events from 203.0.113.246 touching up to 40 distinct ports in a 5-min window against web-01.
  - [Brute-force / password-spraying attack] 29 failed logins from 203.0.113.246 against web-01 within 2.6 min (21 distinct account(s)); peak 29 failures in a 5-min window.
  - [Successful login following hostile activity (probable credential compromise)] successful login for 'user32' from 203.0.113.246 after hostile activity from the same source.
  - [Privilege escalation] privilege escalation by 'www-data' on web-01, occurring after earlier alerts in this incident.
  - [Unexpected account creation (persistence)] new account 'backdoor' created on web-01 during hostile activity.
  - [Large outbound data transfer (possible exfiltration)] 846 MB sent out in 1 transfer(s) from 10.0.1.10 to external-egress.
  - Multi-stage chain: Reconnaissance → Initial Access → Privilege Escalation / Persistence → Exfiltration – linked by shared source IP / pivot through compromised asset.
  - Model confidence: mean P(suspicious)=0.99, min=0.69.
  - Threat intel: 203.0.113.246 listed as brute-force (confidence 79, synthetic-demo-feed)
- **Sample evidence:**
  - #3856 2026-09-17T01:37:32 203.0.113.246 → web-01:34715 firewall_deny user=- status=blocked P=1.00
  - #3873 2026-09-17T01:38:13 203.0.113.246 → web-01:58021 firewall_deny user=- status=blocked P=1.00
  - #3875 2026-09-17T01:38:18 203.0.113.246 → web-01:33143 firewall_deny user=- status=blocked P=1.00
  - #3876 2026-09-17T01:38:20 203.0.113.246 → web-01:40208 firewall_deny user=- status=blocked P=1.00
  - #3877 2026-09-17T01:38:22 203.0.113.246 → web-01:28365 firewall_deny user=- status=blocked P=1.00

### INC-0013 – Critical

- **Window:** 2026-09-18T00:20:40 → 2026-09-18T00:23:53 (193s)
- **Sources:** 203.0.113.247  **Assets:** vpn-gw
- **Kill-chain stages:** Initial Access  **Alerts:** 73 (mean P=0.9937)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 72 failed logins from 203.0.113.247 against vpn-gw within 2.8 min (1 distinct account(s)); peak 72 failures in a 5-min window.
  - [Successful login following hostile activity (probable credential compromise)] successful login for 'user36' from 203.0.113.247 after hostile activity from the same source.
  - Model confidence: mean P(suspicious)=0.99, min=0.96.
  - Threat intel: 203.0.113.247 listed as c2 (confidence 94, synthetic-demo-feed)
- **Sample evidence:**
  - #6091 2026-09-18T00:22:06 203.0.113.247 → vpn-gw:443 login_failed user=user36 status=failure P=1.00
  - #6093 2026-09-18T00:22:11 203.0.113.247 → vpn-gw:443 login_failed user=user36 status=failure P=1.00
  - #6094 2026-09-18T00:22:13 203.0.113.247 → vpn-gw:443 login_failed user=user36 status=failure P=1.00
  - #6124 2026-09-18T00:23:25 203.0.113.247 → vpn-gw:443 login_failed user=user36 status=failure P=1.00
  - #6125 2026-09-18T00:23:28 203.0.113.247 → vpn-gw:443 login_failed user=user36 status=failure P=1.00

### INC-0021 – Critical

- **Window:** 2026-09-19T22:18:36 → 2026-09-19T22:36:36 (1080s)
- **Sources:** 10.1.0.23  **Assets:** external-egress, file-01
- **Kill-chain stages:** Collection → Exfiltration  **Alerts:** 89 (mean P=0.9804)
- **Why it was flagged:**
  - [Bulk file access (possible data staging)] 84 file-access events by 1 user(s) from 10.1.0.23 within 2.8 min (peak 84 events in 5 min, off-hours=True).
  - [Large outbound data transfer (possible exfiltration)] 25,103 MB sent out in 5 transfer(s) from 10.1.0.23 to external-egress.
  - Multi-stage chain: Collection → Exfiltration – linked by shared source IP / pivot through compromised asset.
  - Model confidence: mean P(suspicious)=0.98, min=0.38.
- **Sample evidence:**
  - #9132 2026-09-19T22:21:08 10.1.0.23 → file-01:445 file_access user=user20 status=success P=1.00
  - #9136 2026-09-19T22:21:16 10.1.0.23 → file-01:445 file_access user=user20 status=success P=1.00
  - #9137 2026-09-19T22:21:18 10.1.0.23 → file-01:445 file_access user=user20 status=success P=1.00
  - #9138 2026-09-19T22:21:20 10.1.0.23 → file-01:445 file_access user=user20 status=success P=1.00
  - #9139 2026-09-19T22:21:22 10.1.0.23 → file-01:445 file_access user=user20 status=success P=1.00

### INC-0022 – Critical

- **Window:** 2026-09-19T22:39:26 → 2026-09-19T23:00:24 (1258s)
- **Sources:** 10.1.0.48  **Assets:** external-egress, file-01
- **Kill-chain stages:** Collection → Exfiltration  **Alerts:** 68 (mean P=0.9784)
- **Why it was flagged:**
  - [Bulk file access (possible data staging)] 62 file-access events by 1 user(s) from 10.1.0.48 within 2.0 min (peak 63 events in 5 min, off-hours=True).
  - [Large outbound data transfer (possible exfiltration)] 27,249 MB sent out in 6 transfer(s) from 10.1.0.48 to external-egress.
  - Multi-stage chain: Collection → Exfiltration – linked by shared source IP / pivot through compromised asset.
  - Model confidence: mean P(suspicious)=0.98, min=0.51.
- **Sample evidence:**
  - #9162 2026-09-19T22:39:56 10.1.0.48 → file-01:445 file_access user=user12 status=success P=1.00
  - #9166 2026-09-19T22:40:04 10.1.0.48 → file-01:445 file_access user=user12 status=success P=1.00
  - #9173 2026-09-19T22:40:18 10.1.0.48 → file-01:445 file_access user=user12 status=success P=1.00
  - #9188 2026-09-19T22:40:48 10.1.0.48 → file-01:445 file_access user=user12 status=success P=1.00
  - #9200 2026-09-19T22:41:12 10.1.0.48 → file-01:445 file_access user=user12 status=success P=1.00

### INC-0029 – Critical

- **Window:** 2026-09-21T22:05:06 → 2026-09-21T22:17:02 (716s)
- **Sources:** 10.1.0.37  **Assets:** external-egress, file-01
- **Kill-chain stages:** Collection → Exfiltration  **Alerts:** 136 (mean P=0.992)
- **Why it was flagged:**
  - [Bulk file access (possible data staging)] 133 file-access events by 1 user(s) from 10.1.0.37 within 4.4 min (peak 135 events in 5 min, off-hours=True).
  - [Large outbound data transfer (possible exfiltration)] 13,435 MB sent out in 3 transfer(s) from 10.1.0.37 to external-egress.
  - Multi-stage chain: Collection → Exfiltration – linked by shared source IP / pivot through compromised asset.
  - Model confidence: mean P(suspicious)=0.99, min=0.74.
- **Sample evidence:**
  - #12028 2026-09-21T22:06:04 10.1.0.37 → file-01:445 file_access user=user02 status=success P=1.00
  - #12029 2026-09-21T22:06:06 10.1.0.37 → file-01:445 file_access user=user02 status=success P=1.00
  - #12063 2026-09-21T22:07:14 10.1.0.37 → file-01:445 file_access user=user02 status=success P=1.00
  - #12091 2026-09-21T22:08:10 10.1.0.37 → file-01:445 file_access user=user02 status=success P=1.00
  - #12116 2026-09-21T22:09:00 10.1.0.37 → file-01:445 file_access user=user02 status=success P=1.00

### INC-0006 – High

- **Window:** 2026-09-17T00:36:05 → 2026-09-17T00:42:36 (391s)
- **Sources:** 198.51.100.24  **Assets:** web-01
- **Kill-chain stages:** Initial Access  **Alerts:** 11 (mean P=0.9958)
- **Why it was flagged:**
  - [Web application attack (SQL injection)] 11 SQL-injection attempts from 198.51.100.24 on web-01 over 6.5 min (0 not blocked).
  - Model confidence: mean P(suspicious)=1.00, min=0.98.
- **Sample evidence:**
  - #3821 2026-09-17T00:37:23 198.51.100.24 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00
  - #3823 2026-09-17T00:38:41 198.51.100.24 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00
  - #3824 2026-09-17T00:39:21 198.51.100.24 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00
  - #3825 2026-09-17T00:40:00 198.51.100.24 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00
  - #3828 2026-09-17T00:41:57 198.51.100.24 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00

### INC-0010 – High

- **Window:** 2026-09-17T16:19:43 → 2026-09-17T16:25:27 (344s)
- **Sources:** 203.0.113.212  **Assets:** web-01
- **Kill-chain stages:** Initial Access  **Alerts:** 64 (mean P=0.9932)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 63 failed logins from 203.0.113.212 against web-01 within 5.3 min (1 distinct account(s)); peak 59 failures in a 5-min window.
  - [Successful login following hostile activity (probable credential compromise)] successful login for 'user09' from 203.0.113.212 after hostile activity from the same source.
  - Model confidence: mean P(suspicious)=0.99, min=0.79.
- **Sample evidence:**
  - #5611 2026-09-17T16:21:00 203.0.113.212 → web-01:443 login_failed user=user09 status=failure P=1.00
  - #5615 2026-09-17T16:21:10 203.0.113.212 → web-01:443 login_failed user=user09 status=failure P=1.00
  - #5638 2026-09-17T16:22:43 203.0.113.212 → web-01:443 login_failed user=user09 status=failure P=1.00
  - #5644 2026-09-17T16:23:08 203.0.113.212 → web-01:443 login_failed user=user09 status=failure P=1.00
  - #5651 2026-09-17T16:23:34 203.0.113.212 → web-01:443 login_failed user=user09 status=failure P=1.00

### INC-0012 – High

- **Window:** 2026-09-17T20:43:04 → 2026-09-17T20:43:04 (0s)
- **Sources:** 10.1.1.19  **Assets:** ws-59
- **Kill-chain stages:** Execution / Command & Control  **Alerts:** 1 (mean P=0.4786)
- **Why it was flagged:**
  - [Malware detected on endpoint] malware detection on ws-59 (source host 10.1.1.19).
  - Model confidence: mean P(suspicious)=0.48, min=0.48.
- **Sample evidence:**
  - #5949 2026-09-17T20:43:04 10.1.1.19 → ws-59:0 malware_detected user=user01 status=blocked P=0.48

### INC-0014 – High

- **Window:** 2026-09-18T02:31:38 → 2026-09-18T02:36:14 (276s)
- **Sources:** 192.0.2.193  **Assets:** web-01
- **Kill-chain stages:** Initial Access  **Alerts:** 18 (mean P=0.9962)
- **Why it was flagged:**
  - [Web application attack (SQL injection)] 18 SQL-injection attempts from 192.0.2.193 on web-01 over 4.6 min (2 not blocked).
  - Model confidence: mean P(suspicious)=1.00, min=0.95.
  - Threat intel: 192.0.2.193 listed as c2 (confidence 60, synthetic-demo-feed)
- **Sample evidence:**
  - #6148 2026-09-18T02:33:48 192.0.2.193 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00
  - #6149 2026-09-18T02:34:04 192.0.2.193 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00
  - #6154 2026-09-18T02:35:25 192.0.2.193 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00
  - #6155 2026-09-18T02:35:42 192.0.2.193 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00
  - #6156 2026-09-18T02:35:58 192.0.2.193 → web-01:443 sql_injection_attempt user=- status=blocked P=1.00

### INC-0015 – High

- **Window:** 2026-09-18T02:53:48 → 2026-09-18T02:59:59 (371s)
- **Sources:** 203.0.113.160  **Assets:** ad-01
- **Kill-chain stages:** Initial Access  **Alerts:** 77 (mean P=0.9912)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 76 failed logins from 203.0.113.160 against ad-01 within 5.8 min (1 distinct account(s)); peak 66 failures in a 5-min window.
  - [Successful login following hostile activity (probable credential compromise)] successful login for 'user05' from 203.0.113.160 after hostile activity from the same source.
  - Model confidence: mean P(suspicious)=0.99, min=0.94.
- **Sample evidence:**
  - #6181 2026-09-18T02:55:35 203.0.113.160 → ad-01:389 login_failed user=user05 status=failure P=1.00
  - #6183 2026-09-18T02:55:44 203.0.113.160 → ad-01:389 login_failed user=user05 status=failure P=1.00
  - #6184 2026-09-18T02:55:48 203.0.113.160 → ad-01:389 login_failed user=user05 status=failure P=1.00
  - #6185 2026-09-18T02:55:53 203.0.113.160 → ad-01:389 login_failed user=user05 status=failure P=1.00
  - #6196 2026-09-18T02:56:44 203.0.113.160 → ad-01:389 login_failed user=user05 status=failure P=1.00

### INC-0017 – High

- **Window:** 2026-09-19T01:30:44 → 2026-09-19T01:56:41 (1557s)
- **Sources:** 10.1.1.14  **Assets:** external-egress, ws-54
- **Kill-chain stages:** Execution / Command & Control  **Alerts:** 25 (mean P=0.9761)
- **Why it was flagged:**
  - [Periodic outbound beaconing (possible C2)] 24 near-periodic outbound connections from internal host 10.1.1.14 (inter-arrival CV≈0.10, low variance = automated beaconing).
  - [Malware detected on endpoint] malware detection on ws-54 (source host 10.1.1.14).
  - Model confidence: mean P(suspicious)=0.98, min=0.84.
- **Sample evidence:**
  - #8115 2026-09-19T01:37:05 10.1.1.14 → external-egress:8443 web_request user=- status=success P=0.99
  - #8118 2026-09-19T01:40:28 10.1.1.14 → external-egress:8443 web_request user=- status=success P=0.99
  - #8127 2026-09-19T01:49:09 10.1.1.14 → external-egress:8443 web_request user=- status=success P=0.99
  - #8130 2026-09-19T01:52:19 10.1.1.14 → external-egress:8443 web_request user=- status=success P=0.99
  - #8133 2026-09-19T01:55:42 10.1.1.14 → external-egress:8443 web_request user=- status=success P=0.99

### INC-0023 – High

- **Window:** 2026-09-20T02:27:08 → 2026-09-20T02:31:43 (275s)
- **Sources:** 198.51.100.135  **Assets:** web-01
- **Kill-chain stages:** Initial Access  **Alerts:** 74 (mean P=0.9923)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 73 failed logins from 198.51.100.135 against web-01 within 4.2 min (1 distinct account(s)); peak 73 failures in a 5-min window.
  - [Successful login following hostile activity (probable credential compromise)] successful login for 'user21' from 198.51.100.135 after hostile activity from the same source.
  - Model confidence: mean P(suspicious)=0.99, min=0.90.
  - Threat intel: 198.51.100.135 listed as c2 (confidence 70, synthetic-demo-feed)
- **Sample evidence:**
  - #9270 2026-09-20T02:29:13 198.51.100.135 → web-01:443 login_failed user=user21 status=failure P=1.00
  - #9271 2026-09-20T02:29:17 198.51.100.135 → web-01:443 login_failed user=user21 status=failure P=1.00
  - #9285 2026-09-20T02:30:06 198.51.100.135 → web-01:443 login_failed user=user21 status=failure P=1.00
  - #9304 2026-09-20T02:31:12 198.51.100.135 → web-01:443 login_failed user=user21 status=failure P=1.00
  - #9305 2026-09-20T02:31:16 198.51.100.135 → web-01:443 login_failed user=user21 status=failure P=1.00

### INC-0025 – High

- **Window:** 2026-09-21T04:39:31 → 2026-09-21T04:43:00 (209s)
- **Sources:** 203.0.113.51  **Assets:** vpn-gw
- **Kill-chain stages:** Initial Access  **Alerts:** 76 (mean P=0.9979)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 75 failed logins from 203.0.113.51 against vpn-gw within 3.1 min (1 distinct account(s)); peak 75 failures in a 5-min window.
  - [Successful login following hostile activity (probable credential compromise)] successful login for 'user10' from 203.0.113.51 after hostile activity from the same source.
  - Model confidence: mean P(suspicious)=1.00, min=0.94.
- **Sample evidence:**
  - #10168 2026-09-21T04:41:07 203.0.113.51 → vpn-gw:443 login_failed user=user10 status=failure P=1.00
  - #10174 2026-09-21T04:41:22 203.0.113.51 → vpn-gw:443 login_failed user=user10 status=failure P=1.00
  - #10178 2026-09-21T04:41:32 203.0.113.51 → vpn-gw:443 login_failed user=user10 status=failure P=1.00
  - #10179 2026-09-21T04:41:34 203.0.113.51 → vpn-gw:443 login_failed user=user10 status=failure P=1.00
  - #10180 2026-09-21T04:41:37 203.0.113.51 → vpn-gw:443 login_failed user=user10 status=failure P=1.00

### INC-0026 – High

- **Window:** 2026-09-21T06:43:19 → 2026-09-21T06:43:19 (0s)
- **Sources:** 10.1.1.14  **Assets:** ws-54
- **Kill-chain stages:** Execution / Command & Control  **Alerts:** 1 (mean P=0.5766)
- **Why it was flagged:**
  - [Malware detected on endpoint] malware detection on ws-54 (source host 10.1.1.14).
  - Model confidence: mean P(suspicious)=0.58, min=0.58.
- **Sample evidence:**
  - #10274 2026-09-21T06:43:19 10.1.1.14 → ws-54:0 malware_detected user=user21 status=blocked P=0.58

### INC-0001 – Medium

- **Window:** 2026-09-15T00:17:44 → 2026-09-15T00:19:45 (121s)
- **Sources:** 203.0.113.24  **Assets:** web-01
- **Kill-chain stages:** Initial Access  **Alerts:** 51 (mean P=0.99)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 51 failed logins from 203.0.113.24 against web-01 within 2.0 min (1 distinct account(s)); peak 51 failures in a 5-min window.
  - Model confidence: mean P(suspicious)=0.99, min=0.93.
  - Threat intel: 203.0.113.24 listed as brute-force (confidence 64, synthetic-demo-feed)
- **Sample evidence:**
  - #25 2026-09-15T00:18:42 203.0.113.24 → web-01:443 login_failed user=user16 status=failure P=0.99
  - #26 2026-09-15T00:18:44 203.0.113.24 → web-01:443 login_failed user=user16 status=failure P=0.99
  - #28 2026-09-15T00:18:49 203.0.113.24 → web-01:443 login_failed user=user16 status=failure P=0.99
  - #29 2026-09-15T00:18:52 203.0.113.24 → web-01:443 login_failed user=user16 status=failure P=0.99
  - #30 2026-09-15T00:18:54 203.0.113.24 → web-01:443 login_failed user=user16 status=failure P=0.99

### INC-0002 – Medium

- **Window:** 2026-09-15T08:51:35 → 2026-09-15T08:56:03 (268s)
- **Sources:** 198.51.100.140  **Assets:** vpn-gw
- **Kill-chain stages:** Initial Access  **Alerts:** 43 (mean P=0.9893)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 43 failed logins from 198.51.100.140 against vpn-gw within 4.5 min (26 distinct account(s)); peak 43 failures in a 5-min window.
  - Model confidence: mean P(suspicious)=0.99, min=0.77.
  - Threat intel: 198.51.100.140 listed as scanner (confidence 73, synthetic-demo-feed)
- **Sample evidence:**
  - #293 2026-09-15T08:53:43 198.51.100.140 → vpn-gw:443 login_failed user=user12 status=failure P=1.00
  - #294 2026-09-15T08:53:49 198.51.100.140 → vpn-gw:443 login_failed user=user29 status=failure P=1.00
  - #296 2026-09-15T08:54:02 198.51.100.140 → vpn-gw:443 login_failed user=user13 status=failure P=1.00
  - #297 2026-09-15T08:54:08 198.51.100.140 → vpn-gw:443 login_failed user=user30 status=failure P=1.00
  - #299 2026-09-15T08:54:21 198.51.100.140 → vpn-gw:443 login_failed user=user11 status=failure P=1.00

### INC-0020 – Medium

- **Window:** 2026-09-19T11:33:00 → 2026-09-19T11:37:57 (297s)
- **Sources:** 198.51.100.135  **Assets:** ad-01
- **Kill-chain stages:** Initial Access  **Alerts:** 31 (mean P=0.9821)
- **Why it was flagged:**
  - [Brute-force / password-spraying attack] 31 failed logins from 198.51.100.135 against ad-01 within 5.0 min (1 distinct account(s)); peak 31 failures in a 5-min window.
  - Model confidence: mean P(suspicious)=0.98, min=0.72.
  - Threat intel: 198.51.100.135 listed as c2 (confidence 70, synthetic-demo-feed)
- **Sample evidence:**
  - #8585 2026-09-19T11:35:28 198.51.100.135 → ad-01:389 login_failed user=user31 status=failure P=1.00
  - #8586 2026-09-19T11:35:38 198.51.100.135 → ad-01:389 login_failed user=user31 status=failure P=1.00
  - #8600 2026-09-19T11:37:27 198.51.100.135 → ad-01:389 login_failed user=user31 status=failure P=1.00
  - #8601 2026-09-19T11:37:37 198.51.100.135 → ad-01:389 login_failed user=user31 status=failure P=1.00
  - #8602 2026-09-19T11:37:47 198.51.100.135 → ad-01:389 login_failed user=user31 status=failure P=1.00

### INC-0027 – Medium

- **Window:** 2026-09-21T12:28:51 → 2026-09-21T12:31:19 (148s)
- **Sources:** 198.51.100.57  **Assets:** file-01
- **Kill-chain stages:** Reconnaissance  **Alerts:** 73 (mean P=0.995)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 73 blocked/scan events from 198.51.100.57 touching up to 73 distinct ports in a 5-min window against file-01.
  - Model confidence: mean P(suspicious)=1.00, min=0.77.
  - Threat intel: 198.51.100.57 listed as brute-force (confidence 92, synthetic-demo-feed)
- **Sample evidence:**
  - #10961 2026-09-21T12:29:16 198.51.100.57 → file-01:32158 firewall_deny user=- status=blocked P=1.00
  - #10982 2026-09-21T12:29:55 198.51.100.57 → file-01:16004 firewall_deny user=- status=blocked P=1.00
  - #10987 2026-09-21T12:30:05 198.51.100.57 → file-01:15990 firewall_deny user=- status=blocked P=1.00
  - #10997 2026-09-21T12:30:25 198.51.100.57 → file-01:50348 firewall_deny user=- status=blocked P=1.00
  - #11000 2026-09-21T12:30:32 198.51.100.57 → file-01:33272 firewall_deny user=- status=blocked P=1.00

### INC-0005 – Low

- **Window:** 2026-09-16T04:43:31 → 2026-09-16T04:45:55 (144s)
- **Sources:** 203.0.113.160  **Assets:** web-01
- **Kill-chain stages:** Reconnaissance  **Alerts:** 55 (mean P=0.9921)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 55 blocked/scan events from 203.0.113.160 touching up to 56 distinct ports in a 5-min window against web-01.
  - Model confidence: mean P(suspicious)=0.99, min=0.72.
- **Sample evidence:**
  - #2057 2026-09-16T04:44:22 203.0.113.160 → web-01:48653 firewall_deny user=- status=blocked P=1.00
  - #2060 2026-09-16T04:44:30 203.0.113.160 → web-01:51406 firewall_deny user=- status=blocked P=1.00
  - #2062 2026-09-16T04:44:35 203.0.113.160 → web-01:62645 firewall_deny user=- status=blocked P=1.00
  - #2084 2026-09-16T04:45:34 203.0.113.160 → web-01:10259 firewall_deny user=- status=blocked P=1.00
  - #2092 2026-09-16T04:45:55 203.0.113.160 → web-01:22408 firewall_deny user=- status=blocked P=1.00

### INC-0008 – Low

- **Window:** 2026-09-17T04:20:39 → 2026-09-17T04:22:53 (134s)
- **Sources:** 203.0.113.22  **Assets:** backup-01
- **Kill-chain stages:** Reconnaissance  **Alerts:** 199 (mean P=0.9937)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 199 blocked/scan events from 203.0.113.22 touching up to 199 distinct ports in a 5-min window against backup-01.
  - Model confidence: mean P(suspicious)=0.99, min=0.62.
- **Sample evidence:**
  - #4025 2026-09-17T04:21:46 203.0.113.22 → backup-01:40560 firewall_deny user=- status=blocked P=1.00
  - #4045 2026-09-17T04:21:59 203.0.113.22 → backup-01:28779 firewall_deny user=- status=blocked P=1.00
  - #4048 2026-09-17T04:22:01 203.0.113.22 → backup-01:35884 firewall_deny user=- status=blocked P=1.00
  - #4047 2026-09-17T04:22:01 203.0.113.22 → backup-01:59540 firewall_deny user=- status=blocked P=1.00
  - #4051 2026-09-17T04:22:03 203.0.113.22 → backup-01:25393 firewall_deny user=- status=blocked P=1.00

### INC-0009 – Low

- **Window:** 2026-09-17T09:44:37 → 2026-09-17T09:46:30 (113s)
- **Sources:** 203.0.113.108  **Assets:** db-01
- **Kill-chain stages:** Reconnaissance  **Alerts:** 144 (mean P=0.9949)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 144 blocked/scan events from 203.0.113.108 touching up to 144 distinct ports in a 5-min window against db-01.
  - Model confidence: mean P(suspicious)=0.99, min=0.63.
- **Sample evidence:**
  - #4446 2026-09-17T09:44:58 203.0.113.108 → db-01:58302 firewall_deny user=- status=blocked P=1.00
  - #4451 2026-09-17T09:45:02 203.0.113.108 → db-01:22513 firewall_deny user=- status=blocked P=1.00
  - #4452 2026-09-17T09:45:03 203.0.113.108 → db-01:26068 firewall_deny user=- status=blocked P=1.00
  - #4481 2026-09-17T09:45:25 203.0.113.108 → db-01:36349 port_scan_detected user=- status=blocked P=1.00
  - #4483 2026-09-17T09:45:26 203.0.113.108 → db-01:47119 port_scan_detected user=- status=blocked P=1.00

### INC-0011 – Low

- **Window:** 2026-09-17T16:50:40 → 2026-09-17T16:50:40 (0s)
- **Sources:** 10.1.0.36  **Assets:** file-01
- **Kill-chain stages:** Collection  **Alerts:** 1 (mean P=0.5262)
- **Why it was flagged:**
  - [Bulk file access (possible data staging)] 1 file-access events by 1 user(s) from 10.1.0.36 within 0s (peak 3 events in 5 min, off-hours=False).
  - Model confidence: mean P(suspicious)=0.53, min=0.53.
- **Sample evidence:**
  - #5717 2026-09-17T16:50:40 10.1.0.36 → file-01:445 file_access user=user25 status=success P=0.53

### INC-0016 – Low

- **Window:** 2026-09-19T01:16:58 → 2026-09-19T01:19:53 (175s)
- **Sources:** 192.0.2.111  **Assets:** db-01
- **Kill-chain stages:** Reconnaissance  **Alerts:** 142 (mean P=0.9929)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 142 blocked/scan events from 192.0.2.111 touching up to 142 distinct ports in a 5-min window against db-01.
  - Model confidence: mean P(suspicious)=0.99, min=0.59.
  - Threat intel: 192.0.2.111 listed as web-attacker (confidence 78, synthetic-demo-feed)
- **Sample evidence:**
  - #8049 2026-09-19T01:18:44 192.0.2.111 → db-01:47404 firewall_deny user=- status=blocked P=1.00
  - #8062 2026-09-19T01:19:00 192.0.2.111 → db-01:35067 firewall_deny user=- status=blocked P=1.00
  - #8071 2026-09-19T01:19:11 192.0.2.111 → db-01:59842 port_scan_detected user=- status=blocked P=1.00
  - #8080 2026-09-19T01:19:22 192.0.2.111 → db-01:28556 port_scan_detected user=- status=blocked P=1.00
  - #8083 2026-09-19T01:19:26 192.0.2.111 → db-01:58604 port_scan_detected user=- status=blocked P=1.00

### INC-0018 – Low

- **Window:** 2026-09-19T03:01:27 → 2026-09-19T03:03:06 (99s)
- **Sources:** 203.0.113.212  **Assets:** app-01
- **Kill-chain stages:** Reconnaissance  **Alerts:** 67 (mean P=0.9698)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 67 blocked/scan events from 203.0.113.212 touching up to 67 distinct ports in a 5-min window against app-01.
  - Model confidence: mean P(suspicious)=0.97, min=0.58.
- **Sample evidence:**
  - #8147 2026-09-19T03:01:33 203.0.113.212 → app-01:35922 firewall_deny user=- status=blocked P=0.99
  - #8152 2026-09-19T03:01:41 203.0.113.212 → app-01:34678 port_scan_detected user=- status=blocked P=0.99
  - #8193 2026-09-19T03:02:41 203.0.113.212 → app-01:4748 firewall_deny user=- status=blocked P=0.98
  - #8196 2026-09-19T03:02:45 203.0.113.212 → app-01:22669 firewall_deny user=- status=blocked P=0.98
  - #8210 2026-09-19T03:03:06 203.0.113.212 → app-01:14755 firewall_deny user=- status=blocked P=0.99

### INC-0019 – Low

- **Window:** 2026-09-19T03:53:03 → 2026-09-19T03:54:29 (86s)
- **Sources:** 203.0.113.133  **Assets:** vpn-gw
- **Kill-chain stages:** Reconnaissance  **Alerts:** 139 (mean P=0.9943)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 139 blocked/scan events from 203.0.113.133 touching up to 139 distinct ports in a 5-min window against vpn-gw.
  - Model confidence: mean P(suspicious)=0.99, min=0.51.
  - Threat intel: 203.0.113.133 listed as scanner (confidence 66, synthetic-demo-feed)
- **Sample evidence:**
  - #8241 2026-09-19T03:53:18 203.0.113.133 → vpn-gw:42454 port_scan_detected user=- status=blocked P=1.00
  - #8262 2026-09-19T03:53:32 203.0.113.133 → vpn-gw:23138 port_scan_detected user=- status=blocked P=1.00
  - #8265 2026-09-19T03:53:33 203.0.113.133 → vpn-gw:52061 port_scan_detected user=- status=blocked P=1.00
  - #8271 2026-09-19T03:53:37 203.0.113.133 → vpn-gw:25935 port_scan_detected user=- status=blocked P=1.00
  - #8336 2026-09-19T03:54:18 203.0.113.133 → vpn-gw:50267 port_scan_detected user=- status=blocked P=1.00

### INC-0024 – Informational

- **Window:** 2026-09-21T03:00:00 → 2026-09-21T03:00:00 (0s)
- **Sources:** 10.0.50.5  **Assets:** backup-01
- **Kill-chain stages:** Reconnaissance  **Alerts:** 2 (mean P=0.4063)
- **Why it was flagged:**
  - [Network reconnaissance / port scanning] 2 blocked/scan events from 10.0.50.5 touching up to 2 distinct ports in a 5-min window against backup-01.
  - Model confidence: mean P(suspicious)=0.41, min=0.39.
- **Sample evidence:**
  - #9999 2026-09-21T03:00:00 10.0.50.5 → backup-01:2064 port_scan_detected user=scanner status=blocked P=0.42
  - #10000 2026-09-21T03:00:00 10.0.50.5 → backup-01:5924 port_scan_detected user=scanner status=blocked P=0.39

### INC-0028 – Informational

- **Window:** 2026-09-21T21:00:00 → 2026-09-21T21:00:00 (0s)
- **Sources:** 34.153.75.55  **Assets:** web-01
- **Kill-chain stages:** Unclassified  **Alerts:** 1 (mean P=0.645)
- **Why it was flagged:**
  - [Anomalous activity] 1 anomalous event(s) from 34.153.75.55.
  - Model confidence: mean P(suspicious)=0.65, min=0.65.
- **Sample evidence:**
  - #11953 2026-09-21T21:00:00 34.153.75.55 → web-01:443 web_request user=- status=success P=0.65

## 4. Compliance-mapped findings

### F-0004 – Large outbound data transfer (possible exfiltration) (Critical)

- Incident: INC-0003 · MITRE: TA0010 / T1041 · Assets: external-egress · Events: 3
- NIST CSF 2.0: PR.DS-02 The confidentiality, integrity and availability of data-in-transit are protected; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.12 Data leakage prevention; A.5.14 Information transfer
- Evidence: [Large outbound data transfer (possible exfiltration)] 11,686 MB sent out in 3 transfer(s) from 10.1.0.38 to external-egress. | event_ids: [1932, 1933, 1935]
- Remediation:
  1. Block the egress destination and suspend the transferring account/host.
  1. Determine what data left (DB/file audit logs) and assess breach-notification duties.
  1. Deploy DLP and alerting on volumetric egress anomalies.

### F-0006 – Successful login following hostile activity (probable credential compromise) (Critical)

- Incident: INC-0004 · MITRE: TA0001 / T1078 · Assets: ad-01 · Events: 1
- NIST CSF 2.0: PR.AA-01 Identities and credentials are managed; PR.AA-03 Users, services and hardware are authenticated
- ISO 27001:2022: A.5.16 Identity management; A.8.5 Secure authentication
- Evidence: [Successful login following hostile activity (probable credential compromise)] successful login for 'user39' from 192.0.2.224 after hostile activity from the same source. | event_ids: [2012]
- Remediation:
  1. Disable the account and revoke active sessions/tokens immediately.
  1. Reset credentials, enforce MFA and review everything the account did after login.
  1. Hunt for persistence (new accounts, keys, scheduled tasks) on the target asset.

### F-0010 – Brute-force / password-spraying attack (Critical)

- Incident: INC-0007 · MITRE: TA0001 / T1110 · Assets: web-01 · Events: 29
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 29 failed logins from 203.0.113.246 against web-01 within 2.6 min (21 distinct account(s)); peak 29 failures in a 5-min window. | event_ids: [3880, 3881, 3882, 3883, 3884, 3885, 3886, 3887, 3888, 3889] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0011 – Successful login following hostile activity (probable credential compromise) (Critical)

- Incident: INC-0007 · MITRE: TA0001 / T1078 · Assets: web-01 · Events: 1
- NIST CSF 2.0: PR.AA-01 Identities and credentials are managed; PR.AA-03 Users, services and hardware are authenticated
- ISO 27001:2022: A.5.16 Identity management; A.8.5 Secure authentication
- Evidence: [Successful login following hostile activity (probable credential compromise)] successful login for 'user32' from 203.0.113.246 after hostile activity from the same source. | event_ids: [3909]
- Remediation:
  1. Disable the account and revoke active sessions/tokens immediately.
  1. Reset credentials, enforce MFA and review everything the account did after login.
  1. Hunt for persistence (new accounts, keys, scheduled tasks) on the target asset.

### F-0012 – Privilege escalation (Critical)

- Incident: INC-0007 · MITRE: TA0004 · Assets: web-01 · Events: 1
- NIST CSF 2.0: PR.AA-05 Access permissions follow least privilege and separation of duties
- ISO 27001:2022: A.8.2 Privileged access rights; A.5.15 Access control
- Evidence: [Privilege escalation] privilege escalation by 'www-data' on web-01, occurring after earlier alerts in this incident. | event_ids: [3911]
- Remediation:
  1. Isolate the host; terminate the elevated session.
  1. Audit sudo/admin group membership and remove unnecessary privileges.
  1. Enable privileged-access monitoring and just-in-time admin access.

### F-0013 – Unexpected account creation (persistence) (Critical)

- Incident: INC-0007 · MITRE: TA0003 / T1136 · Assets: web-01 · Events: 1
- NIST CSF 2.0: PR.AA-01 Identities and credentials are managed
- ISO 27001:2022: A.5.16 Identity management; A.5.18 Access rights
- Evidence: [Unexpected account creation (persistence)] new account 'backdoor' created on web-01 during hostile activity. | event_ids: [3912]
- Remediation:
  1. Disable and investigate the new account; verify it against HR/ticketing records.
  1. Alert on account creation outside approved change windows.
  1. Review the creator account's recent activity.

### F-0014 – Large outbound data transfer (possible exfiltration) (Critical)

- Incident: INC-0007 · MITRE: TA0010 / T1041 · Assets: external-egress · Events: 1
- NIST CSF 2.0: PR.DS-02 The confidentiality, integrity and availability of data-in-transit are protected; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.12 Data leakage prevention; A.5.14 Information transfer
- Evidence: [Large outbound data transfer (possible exfiltration)] 846 MB sent out in 1 transfer(s) from 10.0.1.10 to external-egress. | event_ids: [3916]
- Remediation:
  1. Block the egress destination and suspend the transferring account/host.
  1. Determine what data left (DB/file audit logs) and assess breach-notification duties.
  1. Deploy DLP and alerting on volumetric egress anomalies.

### F-0022 – Successful login following hostile activity (probable credential compromise) (Critical)

- Incident: INC-0013 · MITRE: TA0001 / T1078 · Assets: vpn-gw · Events: 1
- NIST CSF 2.0: PR.AA-01 Identities and credentials are managed; PR.AA-03 Users, services and hardware are authenticated
- ISO 27001:2022: A.5.16 Identity management; A.8.5 Secure authentication
- Evidence: [Successful login following hostile activity (probable credential compromise)] successful login for 'user36' from 203.0.113.247 after hostile activity from the same source. | event_ids: [6127]
- Remediation:
  1. Disable the account and revoke active sessions/tokens immediately.
  1. Reset credentials, enforce MFA and review everything the account did after login.
  1. Hunt for persistence (new accounts, keys, scheduled tasks) on the target asset.

### F-0023 – Web application attack (SQL injection) (Critical)

- Incident: INC-0014 · MITRE: TA0001 / T1190 · Assets: web-01 · Events: 18
- NIST CSF 2.0: PR.PS-06 Secure software development practices are integrated and monitored; DE.CM-09 Computing hardware, software and services are monitored
- ISO 27001:2022: A.8.28 Secure coding; A.8.26 Application security requirements
- Evidence: [Web application attack (SQL injection)] 18 SQL-injection attempts from 192.0.2.193 on web-01 over 4.6 min (2 not blocked). | event_ids: [6139, 6140, 6141, 6143, 6144, 6145, 6146, 6147, 6148, 6149] …
- Remediation:
  1. Use parameterised queries / ORM; add input validation on affected endpoints.
  1. Deploy or tighten WAF rules for SQLi; check DB logs for successful injection.
  1. Run SAST/DAST on the application and patch vulnerable components.

### F-0033 – Large outbound data transfer (possible exfiltration) (Critical)

- Incident: INC-0021 · MITRE: TA0010 / T1041 · Assets: external-egress · Events: 5
- NIST CSF 2.0: PR.DS-02 The confidentiality, integrity and availability of data-in-transit are protected; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.12 Data leakage prevention; A.5.14 Information transfer
- Evidence: [Large outbound data transfer (possible exfiltration)] 25,103 MB sent out in 5 transfer(s) from 10.1.0.23 to external-egress. | event_ids: [9140, 9141, 9142, 9143, 9145]
- Remediation:
  1. Block the egress destination and suspend the transferring account/host.
  1. Determine what data left (DB/file audit logs) and assess breach-notification duties.
  1. Deploy DLP and alerting on volumetric egress anomalies.

### F-0035 – Large outbound data transfer (possible exfiltration) (Critical)

- Incident: INC-0022 · MITRE: TA0010 / T1041 · Assets: external-egress · Events: 6
- NIST CSF 2.0: PR.DS-02 The confidentiality, integrity and availability of data-in-transit are protected; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.12 Data leakage prevention; A.5.14 Information transfer
- Evidence: [Large outbound data transfer (possible exfiltration)] 27,249 MB sent out in 6 transfer(s) from 10.1.0.48 to external-egress. | event_ids: [9209, 9210, 9212, 9213, 9214, 9217]
- Remediation:
  1. Block the egress destination and suspend the transferring account/host.
  1. Determine what data left (DB/file audit logs) and assess breach-notification duties.
  1. Deploy DLP and alerting on volumetric egress anomalies.

### F-0037 – Successful login following hostile activity (probable credential compromise) (Critical)

- Incident: INC-0023 · MITRE: TA0001 / T1078 · Assets: web-01 · Events: 1
- NIST CSF 2.0: PR.AA-01 Identities and credentials are managed; PR.AA-03 Users, services and hardware are authenticated
- ISO 27001:2022: A.5.16 Identity management; A.8.5 Secure authentication
- Evidence: [Successful login following hostile activity (probable credential compromise)] successful login for 'user21' from 198.51.100.135 after hostile activity from the same source. | event_ids: [9307]
- Remediation:
  1. Disable the account and revoke active sessions/tokens immediately.
  1. Reset credentials, enforce MFA and review everything the account did after login.
  1. Hunt for persistence (new accounts, keys, scheduled tasks) on the target asset.

### F-0045 – Large outbound data transfer (possible exfiltration) (Critical)

- Incident: INC-0029 · MITRE: TA0010 / T1041 · Assets: external-egress · Events: 3
- NIST CSF 2.0: PR.DS-02 The confidentiality, integrity and availability of data-in-transit are protected; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.12 Data leakage prevention; A.5.14 Information transfer
- Evidence: [Large outbound data transfer (possible exfiltration)] 13,435 MB sent out in 3 transfer(s) from 10.1.0.37 to external-egress. | event_ids: [12132, 12133, 12134]
- Remediation:
  1. Block the egress destination and suspend the transferring account/host.
  1. Determine what data left (DB/file audit logs) and assess breach-notification duties.
  1. Deploy DLP and alerting on volumetric egress anomalies.

### F-0001 – Brute-force / password-spraying attack (High)

- Incident: INC-0001 · MITRE: TA0001 / T1110 · Assets: web-01 · Events: 51
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 51 failed logins from 203.0.113.24 against web-01 within 2.0 min (1 distinct account(s)); peak 51 failures in a 5-min window. | event_ids: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0002 – Brute-force / password-spraying attack (High)

- Incident: INC-0002 · MITRE: TA0001 / T1110 · Assets: vpn-gw · Events: 43
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 43 failed logins from 198.51.100.140 against vpn-gw within 4.5 min (26 distinct account(s)); peak 43 failures in a 5-min window. | event_ids: [270, 271, 274, 275, 276, 277, 278, 279, 280, 281] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0003 – Bulk file access (possible data staging) (High)

- Incident: INC-0003 · MITRE: TA0009 · Assets: file-01 · Events: 116
- NIST CSF 2.0: PR.AA-05 Access permissions follow least privilege and separation of duties; DE.CM-09 Computing hardware, software and services are monitored
- ISO 27001:2022: A.8.3 Information access restriction; A.8.12 Data leakage prevention
- Evidence: [Bulk file access (possible data staging)] 116 file-access events by 1 user(s) from 10.1.0.38 within 3.8 min (peak 117 events in 5 min, off-hours=True). | event_ids: [1816, 1817, 1818, 1819, 1820, 1821, 1822, 1823, 1824, 1825] …
- Remediation:
  1. Review the user's access to the file share; restrict to need-to-know.
  1. Confirm with the user/manager whether the bulk access was expected.
  1. Enable file-access auditing and alerts on unusual volume or off-hours access.

### F-0005 – Brute-force / password-spraying attack (High)

- Incident: INC-0004 · MITRE: TA0001 / T1110 · Assets: ad-01 · Events: 72
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 72 failed logins from 192.0.2.224 against ad-01 within 3.5 min (35 distinct account(s)); peak 72 failures in a 5-min window. | event_ids: [1940, 1941, 1942, 1943, 1944, 1945, 1946, 1947, 1948, 1949] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0008 – Web application attack (SQL injection) (High)

- Incident: INC-0006 · MITRE: TA0001 / T1190 · Assets: web-01 · Events: 11
- NIST CSF 2.0: PR.PS-06 Secure software development practices are integrated and monitored; DE.CM-09 Computing hardware, software and services are monitored
- ISO 27001:2022: A.8.28 Secure coding; A.8.26 Application security requirements
- Evidence: [Web application attack (SQL injection)] 11 SQL-injection attempts from 198.51.100.24 on web-01 over 6.5 min (0 not blocked). | event_ids: [3819, 3820, 3821, 3822, 3823, 3824, 3825, 3826, 3827, 3828] …
- Remediation:
  1. Use parameterised queries / ORM; add input validation on affected endpoints.
  1. Deploy or tighten WAF rules for SQLi; check DB logs for successful injection.
  1. Run SAST/DAST on the application and patch vulnerable components.

### F-0009 – Network reconnaissance / port scanning (High)

- Incident: INC-0007 · MITRE: TA0043 / T1046 · Assets: web-01 · Events: 40
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 40 blocked/scan events from 203.0.113.246 touching up to 40 distinct ports in a 5-min window against web-01. | event_ids: [3838, 3839, 3840, 3841, 3842, 3843, 3844, 3845, 3846, 3847] …
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0018 – Successful login following hostile activity (probable credential compromise) (High)

- Incident: INC-0010 · MITRE: TA0001 / T1078 · Assets: web-01 · Events: 1
- NIST CSF 2.0: PR.AA-01 Identities and credentials are managed; PR.AA-03 Users, services and hardware are authenticated
- ISO 27001:2022: A.5.16 Identity management; A.8.5 Secure authentication
- Evidence: [Successful login following hostile activity (probable credential compromise)] successful login for 'user09' from 203.0.113.212 after hostile activity from the same source. | event_ids: [5672]
- Remediation:
  1. Disable the account and revoke active sessions/tokens immediately.
  1. Reset credentials, enforce MFA and review everything the account did after login.
  1. Hunt for persistence (new accounts, keys, scheduled tasks) on the target asset.

### F-0020 – Malware detected on endpoint (High)

- Incident: INC-0012 · MITRE: TA0002 · Assets: ws-59 · Events: 1
- NIST CSF 2.0: DE.CM-09 Computing hardware, software and services are monitored; RS.MI-02 Incidents are eradicated
- ISO 27001:2022: A.8.7 Protection against malware; A.5.26 Response to information security incidents
- Evidence: [Malware detected on endpoint] malware detection on ws-59 (source host 10.1.1.19). | event_ids: [5949]
- Remediation:
  1. Quarantine the endpoint and run a full EDR scan; collect forensic artefacts.
  1. Block hashes/domains observed; check other hosts for the same indicators.
  1. Reimage the host if persistence cannot be ruled out.

### F-0021 – Brute-force / password-spraying attack (High)

- Incident: INC-0013 · MITRE: TA0001 / T1110 · Assets: vpn-gw · Events: 72
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 72 failed logins from 203.0.113.247 against vpn-gw within 2.8 min (1 distinct account(s)); peak 72 failures in a 5-min window. | event_ids: [6055, 6056, 6057, 6058, 6059, 6060, 6061, 6062, 6063, 6064] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0025 – Successful login following hostile activity (probable credential compromise) (High)

- Incident: INC-0015 · MITRE: TA0001 / T1078 · Assets: ad-01 · Events: 1
- NIST CSF 2.0: PR.AA-01 Identities and credentials are managed; PR.AA-03 Users, services and hardware are authenticated
- ISO 27001:2022: A.5.16 Identity management; A.8.5 Secure authentication
- Evidence: [Successful login following hostile activity (probable credential compromise)] successful login for 'user05' from 203.0.113.160 after hostile activity from the same source. | event_ids: [6234]
- Remediation:
  1. Disable the account and revoke active sessions/tokens immediately.
  1. Reset credentials, enforce MFA and review everything the account did after login.
  1. Hunt for persistence (new accounts, keys, scheduled tasks) on the target asset.

### F-0027 – Malware detected on endpoint (High)

- Incident: INC-0017 · MITRE: TA0002 · Assets: ws-54 · Events: 1
- NIST CSF 2.0: DE.CM-09 Computing hardware, software and services are monitored; RS.MI-02 Incidents are eradicated
- ISO 27001:2022: A.8.7 Protection against malware; A.5.26 Response to information security incidents
- Evidence: [Malware detected on endpoint] malware detection on ws-54 (source host 10.1.1.14). | event_ids: [8109]
- Remediation:
  1. Quarantine the endpoint and run a full EDR scan; collect forensic artefacts.
  1. Block hashes/domains observed; check other hosts for the same indicators.
  1. Reimage the host if persistence cannot be ruled out.

### F-0028 – Periodic outbound beaconing (possible C2) (High)

- Incident: INC-0017 · MITRE: TA0011 · Assets: external-egress · Events: 24
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; DE.AE-02 Potentially adverse events are analyzed
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Periodic outbound beaconing (possible C2)] 24 near-periodic outbound connections from internal host 10.1.1.14 (inter-arrival CV≈0.10, low variance = automated beaconing). | event_ids: [8110, 8111, 8112, 8113, 8114, 8115, 8116, 8117, 8118, 8119] …
- Remediation:
  1. Block the destination at the egress firewall/DNS and isolate the source host.
  1. Capture traffic for analysis; identify the process generating the connections.
  1. Implement egress filtering and TLS inspection for unknown destinations.

### F-0031 – Brute-force / password-spraying attack (High)

- Incident: INC-0020 · MITRE: TA0001 / T1110 · Assets: ad-01 · Events: 31
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 31 failed logins from 198.51.100.135 against ad-01 within 5.0 min (1 distinct account(s)); peak 31 failures in a 5-min window. | event_ids: [8570, 8571, 8572, 8573, 8574, 8575, 8576, 8577, 8578, 8579] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0032 – Bulk file access (possible data staging) (High)

- Incident: INC-0021 · MITRE: TA0009 · Assets: file-01 · Events: 84
- NIST CSF 2.0: PR.AA-05 Access permissions follow least privilege and separation of duties; DE.CM-09 Computing hardware, software and services are monitored
- ISO 27001:2022: A.8.3 Information access restriction; A.8.12 Data leakage prevention
- Evidence: [Bulk file access (possible data staging)] 84 file-access events by 1 user(s) from 10.1.0.23 within 2.8 min (peak 84 events in 5 min, off-hours=True). | event_ids: [9056, 9057, 9058, 9059, 9060, 9061, 9062, 9063, 9064, 9065] …
- Remediation:
  1. Review the user's access to the file share; restrict to need-to-know.
  1. Confirm with the user/manager whether the bulk access was expected.
  1. Enable file-access auditing and alerts on unusual volume or off-hours access.

### F-0034 – Bulk file access (possible data staging) (High)

- Incident: INC-0022 · MITRE: TA0009 · Assets: file-01 · Events: 62
- NIST CSF 2.0: PR.AA-05 Access permissions follow least privilege and separation of duties; DE.CM-09 Computing hardware, software and services are monitored
- ISO 27001:2022: A.8.3 Information access restriction; A.8.12 Data leakage prevention
- Evidence: [Bulk file access (possible data staging)] 62 file-access events by 1 user(s) from 10.1.0.48 within 2.0 min (peak 63 events in 5 min, off-hours=True). | event_ids: [9147, 9148, 9149, 9150, 9151, 9152, 9153, 9154, 9155, 9156] …
- Remediation:
  1. Review the user's access to the file share; restrict to need-to-know.
  1. Confirm with the user/manager whether the bulk access was expected.
  1. Enable file-access auditing and alerts on unusual volume or off-hours access.

### F-0036 – Brute-force / password-spraying attack (High)

- Incident: INC-0023 · MITRE: TA0001 / T1110 · Assets: web-01 · Events: 73
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 73 failed logins from 198.51.100.135 against web-01 within 4.2 min (1 distinct account(s)); peak 73 failures in a 5-min window. | event_ids: [9234, 9235, 9236, 9237, 9238, 9239, 9240, 9241, 9242, 9243] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0040 – Successful login following hostile activity (probable credential compromise) (High)

- Incident: INC-0025 · MITRE: TA0001 / T1078 · Assets: vpn-gw · Events: 1
- NIST CSF 2.0: PR.AA-01 Identities and credentials are managed; PR.AA-03 Users, services and hardware are authenticated
- ISO 27001:2022: A.5.16 Identity management; A.8.5 Secure authentication
- Evidence: [Successful login following hostile activity (probable credential compromise)] successful login for 'user10' from 203.0.113.51 after hostile activity from the same source. | event_ids: [10205]
- Remediation:
  1. Disable the account and revoke active sessions/tokens immediately.
  1. Reset credentials, enforce MFA and review everything the account did after login.
  1. Hunt for persistence (new accounts, keys, scheduled tasks) on the target asset.

### F-0041 – Malware detected on endpoint (High)

- Incident: INC-0026 · MITRE: TA0002 · Assets: ws-54 · Events: 1
- NIST CSF 2.0: DE.CM-09 Computing hardware, software and services are monitored; RS.MI-02 Incidents are eradicated
- ISO 27001:2022: A.8.7 Protection against malware; A.5.26 Response to information security incidents
- Evidence: [Malware detected on endpoint] malware detection on ws-54 (source host 10.1.1.14). | event_ids: [10274]
- Remediation:
  1. Quarantine the endpoint and run a full EDR scan; collect forensic artefacts.
  1. Block hashes/domains observed; check other hosts for the same indicators.
  1. Reimage the host if persistence cannot be ruled out.

### F-0044 – Bulk file access (possible data staging) (High)

- Incident: INC-0029 · MITRE: TA0009 · Assets: file-01 · Events: 133
- NIST CSF 2.0: PR.AA-05 Access permissions follow least privilege and separation of duties; DE.CM-09 Computing hardware, software and services are monitored
- ISO 27001:2022: A.8.3 Information access restriction; A.8.12 Data leakage prevention
- Evidence: [Bulk file access (possible data staging)] 133 file-access events by 1 user(s) from 10.1.0.37 within 4.4 min (peak 135 events in 5 min, off-hours=True). | event_ids: [11999, 12000, 12001, 12002, 12003, 12004, 12005, 12006, 12007, 12008] …
- Remediation:
  1. Review the user's access to the file share; restrict to need-to-know.
  1. Confirm with the user/manager whether the bulk access was expected.
  1. Enable file-access auditing and alerts on unusual volume or off-hours access.

### F-0017 – Brute-force / password-spraying attack (Medium)

- Incident: INC-0010 · MITRE: TA0001 / T1110 · Assets: web-01 · Events: 63
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 63 failed logins from 203.0.113.212 against web-01 within 5.3 min (1 distinct account(s)); peak 59 failures in a 5-min window. | event_ids: [5594, 5595, 5596, 5597, 5598, 5600, 5601, 5602, 5604, 5605] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0019 – Bulk file access (possible data staging) (Medium)

- Incident: INC-0011 · MITRE: TA0009 · Assets: file-01 · Events: 1
- NIST CSF 2.0: PR.AA-05 Access permissions follow least privilege and separation of duties; DE.CM-09 Computing hardware, software and services are monitored
- ISO 27001:2022: A.8.3 Information access restriction; A.8.12 Data leakage prevention
- Evidence: [Bulk file access (possible data staging)] 1 file-access events by 1 user(s) from 10.1.0.36 within 0s (peak 3 events in 5 min, off-hours=False). | event_ids: [5717]
- Remediation:
  1. Review the user's access to the file share; restrict to need-to-know.
  1. Confirm with the user/manager whether the bulk access was expected.
  1. Enable file-access auditing and alerts on unusual volume or off-hours access.

### F-0024 – Brute-force / password-spraying attack (Medium)

- Incident: INC-0015 · MITRE: TA0001 / T1110 · Assets: ad-01 · Events: 76
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 76 failed logins from 203.0.113.160 against ad-01 within 5.8 min (1 distinct account(s)); peak 66 failures in a 5-min window. | event_ids: [6158, 6159, 6160, 6161, 6162, 6163, 6164, 6165, 6166, 6167] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0026 – Network reconnaissance / port scanning (Medium)

- Incident: INC-0016 · MITRE: TA0043 / T1046 · Assets: db-01 · Events: 142
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 142 blocked/scan events from 192.0.2.111 touching up to 142 distinct ports in a 5-min window against db-01. | event_ids: [7964, 7965, 7966, 7967, 7968, 7969, 7970, 7971, 7972, 7973] …
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0030 – Network reconnaissance / port scanning (Medium)

- Incident: INC-0019 · MITRE: TA0043 / T1046 · Assets: vpn-gw · Events: 139
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 139 blocked/scan events from 203.0.113.133 touching up to 139 distinct ports in a 5-min window against vpn-gw. | event_ids: [8216, 8217, 8218, 8219, 8220, 8221, 8222, 8223, 8225, 8224] …
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0039 – Brute-force / password-spraying attack (Medium)

- Incident: INC-0025 · MITRE: TA0001 / T1110 · Assets: vpn-gw · Events: 75
- NIST CSF 2.0: PR.AA-03 Users, services and hardware are authenticated; DE.CM-01 Networks and network services are monitored
- ISO 27001:2022: A.8.5 Secure authentication; A.8.16 Monitoring activities
- Evidence: [Brute-force / password-spraying attack] 75 failed logins from 203.0.113.51 against vpn-gw within 3.1 min (1 distinct account(s)); peak 75 failures in a 5-min window. | event_ids: [10130, 10131, 10132, 10133, 10134, 10135, 10136, 10137, 10138, 10139] …
- Remediation:
  1. Enforce account lockout / rate limiting and MFA on all remote-access services.
  1. Block the offending IP; force password reset for targeted accounts.
  1. Review authentication logs for successful logins from the same source.

### F-0042 – Network reconnaissance / port scanning (Medium)

- Incident: INC-0027 · MITRE: TA0043 / T1046 · Assets: file-01 · Events: 73
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 73 blocked/scan events from 198.51.100.57 touching up to 73 distinct ports in a 5-min window against file-01. | event_ids: [10947, 10949, 10950, 10951, 10952, 10953, 10954, 10955, 10956, 10957] …
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0007 – Network reconnaissance / port scanning (Low)

- Incident: INC-0005 · MITRE: TA0043 / T1046 · Assets: web-01 · Events: 55
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 55 blocked/scan events from 203.0.113.160 touching up to 56 distinct ports in a 5-min window against web-01. | event_ids: [2037, 2038, 2039, 2040, 2041, 2042, 2043, 2044, 2045, 2046] …
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0015 – Network reconnaissance / port scanning (Low)

- Incident: INC-0008 · MITRE: TA0043 / T1046 · Assets: backup-01 · Events: 199
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 199 blocked/scan events from 203.0.113.22 touching up to 199 distinct ports in a 5-min window against backup-01. | event_ids: [3926, 3927, 3928, 3929, 3930, 3931, 3932, 3933, 3935, 3934] …
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0016 – Network reconnaissance / port scanning (Low)

- Incident: INC-0009 · MITRE: TA0043 / T1046 · Assets: db-01 · Events: 144
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 144 blocked/scan events from 203.0.113.108 touching up to 144 distinct ports in a 5-min window against db-01. | event_ids: [4419, 4420, 4421, 4422, 4423, 4424, 4425, 4426, 4427, 4428] …
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0029 – Network reconnaissance / port scanning (Low)

- Incident: INC-0018 · MITRE: TA0043 / T1046 · Assets: app-01 · Events: 67
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 67 blocked/scan events from 203.0.113.212 touching up to 67 distinct ports in a 5-min window against app-01. | event_ids: [8143, 8144, 8145, 8146, 8147, 8148, 8149, 8150, 8151, 8152] …
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0038 – Network reconnaissance / port scanning (Informational)

- Incident: INC-0024 · MITRE: TA0043 / T1046 · Assets: backup-01 · Events: 2
- NIST CSF 2.0: DE.CM-01 Networks and network services are monitored; PR.IR-01 Networks and environments are protected from unauthorized logical access
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.20 Networks security
- Evidence: [Network reconnaissance / port scanning] 2 blocked/scan events from 10.0.50.5 touching up to 2 distinct ports in a 5-min window against backup-01. | event_ids: [9999, 10000]
- Remediation:
  1. Block the source IP at the perimeter firewall / WAF and add it to a deny-list.
  1. Reduce exposed services; close unused ports and restrict management ports to VPN.
  1. Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns.

### F-0043 – Anomalous activity (Informational)

- Incident: INC-0028 · MITRE: - · Assets: web-01 · Events: 1
- NIST CSF 2.0: DE.AE-02 Potentially adverse events are analyzed to understand attack targets and methods
- ISO 27001:2022: A.8.16 Monitoring activities; A.8.15 Logging
- Evidence: [Anomalous activity] 1 anomalous event(s) from 34.153.75.55. | event_ids: [11953]
- Remediation:
  1. Triage manually; confirm whether the behaviour is expected for this user/asset.
  1. Add a detection rule or allow-list entry once understood.
