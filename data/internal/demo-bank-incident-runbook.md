---
title: Demo Bank Incident Response Runbook
roles: security-admin
classification: confidential
---
# Demo Bank Incident Response Runbook

This is a fictional runbook written for demonstration purposes. All names, phone numbers and addresses below are invented.

## 1. Severity levels

Severity 1 (critical): confirmed compromise of Restricted data, ransomware, or an outage of payment services. Severity 2 (high): confirmed compromise of an internal system without impact on Restricted data. Severity 3 (medium): suspicious activity that is not yet confirmed. Severity 4 (low): policy violation without security impact.

## 2. Escalation

A Severity 1 incident is escalated to the CISO within 15 minutes and to the executive committee within 1 hour. The national regulator is notified within 72 hours when personal data is affected. A Severity 2 incident is escalated to the CISO within 4 hours.

## 3. On-call contacts

The on-call SOC analyst can be reached at soc-oncall@demobank.example or +216 70 000 101. The incident manager on duty can be reached at incident-manager@demobank.example or +216 70 000 102. The SIEM server is at 10.20.30.40 and the backup SIEM collector at 10.20.30.41.

## 4. Containment of a compromised workstation

1. Isolate the workstation from the network through the EDR console, without powering it off, to keep memory evidence.
2. Disable the user account in Active Directory and revoke active sessions and tokens.
3. Collect a memory image and the EDR timeline before any cleanup.
4. Block the indicators of compromise (IP addresses, domains, file hashes) on the firewall and the EDR.
5. Reimage the workstation only after the investigation team approves.

## 5. Ransomware

Never pay a ransom without a decision of the executive committee. Disconnect the affected network segments, protect the backups by isolating the backup network, and check the integrity of the last offline backup before any restoration.

## 6. Evidence handling

All evidence is stored in the forensic share with a SHA-256 hash and a chain of custody form. Evidence is kept for at least 5 years.
