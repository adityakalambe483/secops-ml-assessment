"""Security knowledge base: event -> category -> kill-chain stage, MITRE ATT&CK,
NIST CSF 2.0 / ISO 27001:2022 controls and remediation (Task 3).

Control references were written against NIST CSF 2.0 and ISO/IEC 27001:2022 Annex A numbering.
Verify against the official documents before using in a real audit.
"""

RISK = ["Informational", "Low", "Medium", "High", "Critical"]

CATEGORIES = {
    "reconnaissance": {
        "title": "Network reconnaissance / port scanning", "stage": 0, "stage_name": "Reconnaissance",
        "mitre": "TA0043 / T1046", "risk": 1,
        "nist": [("DE.CM-01", "Networks and network services are monitored"),
                 ("PR.IR-01", "Networks and environments are protected from unauthorized logical access")],
        "iso": [("A.8.16", "Monitoring activities"), ("A.8.20", "Networks security")],
        "remediation": ["Block the source IP at the perimeter firewall / WAF and add it to a deny-list.",
                        "Reduce exposed services; close unused ports and restrict management ports to VPN.",
                        "Tune IDS/IPS scan thresholds and alert on horizontal/vertical scan patterns."]},
    "credential_attack": {
        "title": "Brute-force / password-spraying attack", "stage": 1, "stage_name": "Initial Access",
        "mitre": "TA0001 / T1110", "risk": 2,
        "nist": [("PR.AA-03", "Users, services and hardware are authenticated"),
                 ("DE.CM-01", "Networks and network services are monitored")],
        "iso": [("A.8.5", "Secure authentication"), ("A.8.16", "Monitoring activities")],
        "remediation": ["Enforce account lockout / rate limiting and MFA on all remote-access services.",
                        "Block the offending IP; force password reset for targeted accounts.",
                        "Review authentication logs for successful logins from the same source."]},
    "suspicious_login": {
        "title": "Successful login following hostile activity (probable credential compromise)",
        "stage": 1, "stage_name": "Initial Access", "mitre": "TA0001 / T1078", "risk": 3,
        "nist": [("PR.AA-01", "Identities and credentials are managed"),
                 ("PR.AA-03", "Users, services and hardware are authenticated")],
        "iso": [("A.5.16", "Identity management"), ("A.8.5", "Secure authentication")],
        "remediation": ["Disable the account and revoke active sessions/tokens immediately.",
                        "Reset credentials, enforce MFA and review everything the account did after login.",
                        "Hunt for persistence (new accounts, keys, scheduled tasks) on the target asset."]},
    "web_attack": {
        "title": "Web application attack (SQL injection)", "stage": 1, "stage_name": "Initial Access",
        "mitre": "TA0001 / T1190", "risk": 3,
        "nist": [("PR.PS-06", "Secure software development practices are integrated and monitored"),
                 ("DE.CM-09", "Computing hardware, software and services are monitored")],
        "iso": [("A.8.28", "Secure coding"), ("A.8.26", "Application security requirements")],
        "remediation": ["Use parameterised queries / ORM; add input validation on affected endpoints.",
                        "Deploy or tighten WAF rules for SQLi; check DB logs for successful injection.",
                        "Run SAST/DAST on the application and patch vulnerable components."]},
    "privilege_escalation": {
        "title": "Privilege escalation", "stage": 2, "stage_name": "Privilege Escalation / Persistence",
        "mitre": "TA0004", "risk": 3,
        "nist": [("PR.AA-05", "Access permissions follow least privilege and separation of duties")],
        "iso": [("A.8.2", "Privileged access rights"), ("A.5.15", "Access control")],
        "remediation": ["Isolate the host; terminate the elevated session.",
                        "Audit sudo/admin group membership and remove unnecessary privileges.",
                        "Enable privileged-access monitoring and just-in-time admin access."]},
    "persistence_account": {
        "title": "Unexpected account creation (persistence)", "stage": 2,
        "stage_name": "Privilege Escalation / Persistence", "mitre": "TA0003 / T1136", "risk": 3,
        "nist": [("PR.AA-01", "Identities and credentials are managed")],
        "iso": [("A.5.16", "Identity management"), ("A.5.18", "Access rights")],
        "remediation": ["Disable and investigate the new account; verify it against HR/ticketing records.",
                        "Alert on account creation outside approved change windows.",
                        "Review the creator account's recent activity."]},
    "malware": {
        "title": "Malware detected on endpoint", "stage": 3, "stage_name": "Execution / Command & Control",
        "mitre": "TA0002", "risk": 3,
        "nist": [("DE.CM-09", "Computing hardware, software and services are monitored"),
                 ("RS.MI-02", "Incidents are eradicated")],
        "iso": [("A.8.7", "Protection against malware"), ("A.5.26", "Response to information security incidents")],
        "remediation": ["Quarantine the endpoint and run a full EDR scan; collect forensic artefacts.",
                        "Block hashes/domains observed; check other hosts for the same indicators.",
                        "Reimage the host if persistence cannot be ruled out."]},
    "c2_beaconing": {
        "title": "Periodic outbound beaconing (possible C2)", "stage": 3,
        "stage_name": "Execution / Command & Control", "mitre": "TA0011", "risk": 3,
        "nist": [("DE.CM-01", "Networks and network services are monitored"),
                 ("DE.AE-02", "Potentially adverse events are analyzed")],
        "iso": [("A.8.16", "Monitoring activities"), ("A.8.20", "Networks security")],
        "remediation": ["Block the destination at the egress firewall/DNS and isolate the source host.",
                        "Capture traffic for analysis; identify the process generating the connections.",
                        "Implement egress filtering and TLS inspection for unknown destinations."]},
    "data_staging": {
        "title": "Bulk file access (possible data staging)", "stage": 4, "stage_name": "Collection",
        "mitre": "TA0009", "risk": 2,
        "nist": [("PR.AA-05", "Access permissions follow least privilege and separation of duties"),
                 ("DE.CM-09", "Computing hardware, software and services are monitored")],
        "iso": [("A.8.3", "Information access restriction"), ("A.8.12", "Data leakage prevention")],
        "remediation": ["Review the user's access to the file share; restrict to need-to-know.",
                        "Confirm with the user/manager whether the bulk access was expected.",
                        "Enable file-access auditing and alerts on unusual volume or off-hours access."]},
    "data_exfiltration": {
        "title": "Large outbound data transfer (possible exfiltration)", "stage": 4, "stage_name": "Exfiltration",
        "mitre": "TA0010 / T1041", "risk": 4,
        "nist": [("PR.DS-02", "The confidentiality, integrity and availability of data-in-transit are protected"),
                 ("DE.CM-01", "Networks and network services are monitored")],
        "iso": [("A.8.12", "Data leakage prevention"), ("A.5.14", "Information transfer")],
        "remediation": ["Block the egress destination and suspend the transferring account/host.",
                        "Determine what data left (DB/file audit logs) and assess breach-notification duties.",
                        "Deploy DLP and alerting on volumetric egress anomalies."]},
    "anomalous_activity": {
        "title": "Anomalous activity", "stage": 1, "stage_name": "Unclassified", "mitre": "-", "risk": 1,
        "nist": [("DE.AE-02", "Potentially adverse events are analyzed to understand attack targets and methods")],
        "iso": [("A.8.16", "Monitoring activities"), ("A.8.15", "Logging")],
        "remediation": ["Triage manually; confirm whether the behaviour is expected for this user/asset.",
                        "Add a detection rule or allow-list entry once understood."]},
}

# Order in which an incident's narrative lists stages
STAGE_ORDER = ["Reconnaissance", "Initial Access", "Privilege Escalation / Persistence",
               "Execution / Command & Control", "Collection", "Exfiltration", "Unclassified"]


def categorize(event_type: str, src_internal: bool) -> str:
    return {
        "login_failed": "credential_attack",
        "login_success": "suspicious_login",
        "firewall_deny": "reconnaissance",
        "port_scan_detected": "reconnaissance",
        "sql_injection_attempt": "web_attack",
        "priv_escalation": "privilege_escalation",
        "new_account_created": "persistence_account",
        "large_transfer": "data_exfiltration",
        "malware_detected": "malware",
        "file_access": "data_staging",
        "web_request": "c2_beaconing" if src_internal else "anomalous_activity",
        "dns_query": "c2_beaconing" if src_internal else "anomalous_activity",
    }.get(event_type, "anomalous_activity")
