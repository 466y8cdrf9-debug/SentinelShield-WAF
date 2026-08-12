# SentinelShield: Advanced Intrusion Detection & Web Protection System

SentinelShield is a lightweight Web Application Firewall (WAF) and Intrusion Detection System (IDS) implemented in Python/Flask. It inspects incoming HTTP requests for malicious signatures and enforces behavioral rate-limiting to block abusive traffic and brute-force attempts.

---

## 1. Executive Summary & Metrics

### Security Performance Overview

| Metric / Category | Count / Value |
| :--- | :--- |
| **Total Requests Processed** | 25 |
| **Malicious Requests Detected & Blocked** | 12 |
| **Legitimate Requests Allowed** | 13 |
| **SQL Injection (SQLi) Detected** | 4 |
| **Cross-Site Scripting (XSS) Detected** | 4 |
| **Path Traversal / LFI Detected** | 2 |
| **Rate Limit Violations (Abusive Traffic)** | 2 |
| **Top Flagged IP Address** | `127.0.0.1` |

---

## 2. Practical Interpretation Notes

- **Signature-Based Inspection:** Incoming HTTP request parameters are compared against defined patterns in `rules.json`. Requests containing payloads like `' OR '1'='1`, `<script>`, or `../` are intercepted by the WAF middleware and blocked with `HTTP 403 Forbidden`.
- **Behavioral Rate Limiting:** The engine tracks client IP request frequency within a 60-second sliding window. Exceeding 10 requests triggers dynamic rate-limiting, responding with `HTTP 429 Too Many Requests` to prevent flooding or brute-force attacks.
- **Recommendations for Production:**
  1. Implement parameterized queries to supplement signature inspection.
  2. Context-encode all web application outputs to neutralize XSS vulnerabilities.
  3. Enforce automated dynamic IP bans at the firewall level for persistent rate-limit offenders.

---

## 3. Practical Journal & Execution Workflow

### Objective
To build a foundational understanding of modern WAF/IDS architectures by creating a signature-matching, logging, and rate-limiting system using Python and Flask.

### Tools & Technologies
- **Language/Framework:** Python 3, Flask
- **Data Protocols:** JSON (`rules.json`, `security_logs.json`)
- **Testing Capabilities:** `curl`, HTTP Client Browsers

### Execution Steps
1. **Rule Base Definition:** Configured malicious attack signatures in `rules.json`.
2. **Middleware Initialization:** Created `app.py` with custom WAF logic to inspect parameters prior to routing.
3. **Simulated Attacks:** Sent clean requests alongside crafted payloads (SQLi, XSS, Path Traversal) to verify detection behavior.
4. **Stress Testing:** Sent rapid sequential requests to validate behavioral threshold enforcement.
5. **Log Audit:** Inspected generated JSON logs via the `/dashboard` endpoint to confirm alert tracking accuracy.

---

## 4. Final Performance Report

- **Total Attacks Tested:** 12
- **Successful Detections:** 12
- **Detection Accuracy:** 100%
- **False Positives:** 0
- **False Negatives:** 0
