## Potential Impossible Travel Detection (Microsoft Sentinel)

### Overview

This project demonstrates the detection, validation, and investigation of a **Potential Impossible Travel** scenario using Microsoft Sentinel.

The detection identifies user sign-ins from geographically distant locations within a short timeframe — a common indicator of:

* Credential compromise
* VPN/proxy usage
* Account sharing

---

## Detection Logic

### KQL Query

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| extend City = tostring(LocationDetails.city)
| where isnotempty(City)
| summarize Cities = make_set(City), Count = dcount(City), IPs = make_set(IPAddress) by UserPrincipalName
| where Count > 1
```

### Logic Breakdown

* Filters successful sign-ins (`ResultType == 0`)
* Extracts city from login metadata
* Identifies users logging in from **multiple cities within 1 hour**
* Flags accounts with **>1 unique location**

---

## Analytics Rule Configuration

| Setting        | Value                           |
| -------------- | ------------------------------- |
| Frequency      | 5 minutes                       |
| Lookup Period  | 1 hour                          |
| Threshold      | > 0 results                     |
| Tactics        | Initial Access, Defense Evasion |
| Entity Mapping | Account, IP                     |

<p align="left">
  <img src="assets/Screenshot 2026-03-13 121049.png" width="750">
  <img src="assets/Screenshot 2026-03-17 081219.png" width="500">
  <img src="assets/Screenshot 2026-03-17 081901.png" width="750">
  <img src="assets/Screenshot 2026-03-17 081955.png" width="750">
  <img src="assets/Screenshot 2026-03-17 082024.png" width="500">
</p>

---

## Lab Validation (Attack Simulation)

### Step 1 – Local Login

* Logged into Azure from local machine
* Location: **Carlsbad, CA**

<p align="left">
  <img src="assets/Screenshot 2026-03-17 130546.png" width="750">
  <img src="assets/Screenshot 2026-03-17 130603.png" width="750">
  <img src="assets/Screenshot 2026-03-17 130610.png" width="750">
  <img src="assets/Screenshot 2026-03-17 130338.png" width="750">
</p>

---

### Step 2 – Remote Access via Azure VM

* Created Windows 11 VM in **East US (Virginia)**
* Connected via RDP

<p align="left">
  <img src="assets/Screenshot 2026-03-17 084013.png" width="300">
  <img src="assets/Screenshot 2026-03-17 084049.png" width="300">
  <img src="assets/Screenshot 2026-03-17 084055.png" width="300">
</p>

---

### Step 3 – Secondary Login from VM

* Logged into Azure from VM public IP
* Location: **Boydton, VA (20.122.36.194)**

<p align="left">
  <img src="assets/Screenshot 2026-03-17 092346.png" width="750">
  <img src="assets/Screenshot 2026-03-17 092357.png" width="750">
  <img src="assets/Screenshot 2026-03-17 092140.png" width="750">
  <img src="assets/Screenshot 2026-03-17 092447.png" width="750">
</p>

---

### Step 4 – Detection Triggered

* Sentinel detected logins from:

  * Carlsbad, CA
  * Boydton, VA
* Within same time window

<p align="left">
  <img src="assets/Screenshot 2026-03-17 094320.png" width="700">
</p>

---

## Incident Details

* **Incident Name:** Potential Impossible Travel – Jordan
* **Severity:** Medium
* **Alerts:** Multiple correlated alerts
* **Status:** New → Active
* **Workspace:** law-cyber-range

<p align="left">
  <img src="assets/Screenshot 2026-03-17 094414.png" width="700">
  <img src="assets/Screenshot 2026-03-17 094448.png" width="700">
  <img src="assets/Screenshot 2026-03-17 094552.png" width="700">
</p>

---

## Investigation Findings

### Locations Identified

* Carlsbad, California (Local machine)
* Boydton, Virginia (Azure VM)

### IP Addresses

* Local IP (IPv6)
* `20.122.36.194` (Azure VM)

<p align="left">
  <img src="assets/Screenshot 2026-03-17 103857.png" width="700">
  <img src="assets/Screenshot 2026-03-17 104102.png" width="700">
</p>

---

### Entity Graph Analysis

* Single user
* Multiple sign-in sources
* Clear geographic disparity

<p align="left">
  <img src="assets/Screenshot 2026-03-17 095250.png" width="700">
  <img src="assets/Screenshot 2026-03-17 105809.png" width="700">
</p>

---

## Analyst Conclusion

* Sign-ins originated from geographically distant locations within minutes
* Behavior is **not physically possible under normal conditions**
* Activity was **intentionally generated in a controlled lab environment**
* No evidence of compromise, persistence, or malicious behavior

---

## Final Disposition

**Closed as Benign Positive)**

<p align="left">
  <img src="assets/Screenshot 2026-03-17 110441.png" width="700">
  <img src="assets/Screenshot 2026-03-17 105809.png" width="700">
</p>

---

## MITRE ATT&CK Mapping

| Tactic          | Technique                 |
| --------------- | ------------------------- |
| Initial Access  | Valid Accounts (T1078)    |
| Defense Evasion | Obfuscated/Proxy Behavior |

---
