---
title: Demo Bank Information Security Policy
roles: staff, security-admin
classification: internal
---
# Demo Bank Information Security Policy

This is a fictional policy written for demonstration purposes. Demo Bank is not a real organization.

## 1. Scope

This policy applies to all employees, contractors and service providers of Demo Bank who access its information systems, in every office and in remote work.

## 2. Data classification

Demo Bank uses four classification levels: Public, Internal, Confidential and Restricted. Customer account data, card data and identity documents are classified Restricted. Restricted data must be encrypted at rest and in transit and must never be sent to external services, including external AI services, without written approval from the Chief Information Security Officer (CISO).

## 3. Access control

Access is granted on a need-to-know basis with the principle of least privilege. Every access request must be approved by the data owner. Access rights to Restricted systems are reviewed every quarter, and access rights to other systems are reviewed every six months. Accounts of employees who leave the bank are disabled within 24 hours of departure. Shared accounts are prohibited.

## 4. Authentication

Multi-factor authentication (MFA) is mandatory for remote access, for all administrator accounts and for every system that processes Restricted data. Passwords must contain at least 14 characters. Passwords are not changed periodically unless there is evidence of compromise. Accounts are locked for 15 minutes after 5 failed login attempts.

## 5. Logging and monitoring

Security events from servers, firewalls, databases and business applications are sent to the central SIEM. Security logs are kept for 12 months, with the last 3 months available for immediate search. Logs must not contain passwords, full card numbers or authentication tokens.

## 6. Use of AI assistants

Employees may use AI assistants approved by the security team only. Internal and Confidential documents may be processed by an approved AI assistant that runs inside the bank's infrastructure. Restricted data must never be entered into an AI assistant hosted by a third party. Answers produced by an AI assistant must be checked by an employee before they are used in a decision.

## 7. Incident reporting

Every employee must report a suspected security incident to the Security Operations Center within 1 hour of discovery. Reporting is possible by phone, by email or through the incident portal. Employees must not try to investigate an incident on their own.

## 8. Vulnerability management

Critical vulnerabilities on internet-facing systems must be fixed within 7 days, and high vulnerabilities within 30 days. Internal systems are scanned every month. A penetration test of internet-facing applications is performed every year and after every major change.
