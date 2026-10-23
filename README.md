# CyberShield

> **IBM SkillsBuild Cyber Security 2026 — BharatCares Project Submission**
> Author: Kumari Shambhavi

---

## 1. Project Description

CyberShield is a beginner-friendly, simulated cybersecurity monitoring dashboard built with Python and Streamlit. It analyses fictional login activity data to detect IP addresses that exhibit suspicious patterns of repeated failed login attempts. The dashboard assigns risk levels to flagged IPs, displays security alerts, and provides interactive charts and filters for security investigation.

> ⚠️ **Disclaimer:** All data is entirely simulated and fictional. CyberShield does not connect to any real system, database, or external API. It does not perform penetration testing or any form of real attack. Detecting a suspicious pattern does **not** prove that a cyberattack has occurred — every alert requires further human investigation.

---

## 2. Problem Statement

In real-world environments, authentication logs contain thousands of login events. Security analysts must identify IP addresses that repeatedly fail to log in, which can indicate brute-force attacks, credential stuffing, or unauthorized access attempts. Manually reviewing raw logs is time-consuming and error-prone.

CyberShield simulates this scenario using fictional data and demonstrates how a simple, rule-based approach can automatically flag suspicious IP addresses, assign risk levels, and surface them in a clear dashboard — reducing the manual effort required during an initial investigation.

---

## 3. Objectives

- Monitor simulated login activity across multiple IP addresses and usernames
- Count failed login attempts per IP address from the activity log
- Detect suspicious IP addresses using a threshold-based rule (≥ 5 failed attempts)
- Assign risk levels to flagged IPs: **Medium** (5–8 failures) or **High** (9+ failures)
- Display security alerts with IP address, usernames involved, failure count, risk level, and reason
- Visualize login outcomes and per-IP failure counts using interactive charts
- Provide sidebar filters so investigators can focus on specific login results or risk levels
- Present findings in a clean, dark-themed cybersecurity dashboard suitable for demonstration

---

## 4. Technologies Used

| Technology | Purpose |
|---|---|
| **Python 3.10+** | Core programming language |
| **Streamlit** | Web-based interactive dashboard framework |
| **Pandas** | Data manipulation and analysis |

No machine learning, databases, external APIs, authentication systems, or penetration-testing tools are used.

---

## 5. Dataset

The project uses a **simulated login activity dataset generated entirely within the application** for educational and demonstration purposes. It does **not** contain real user credentials or real authentication data.

### How the dataset is generated

1. **Random records (50 rows):** A reproducible random generator (`random.seed(42)`) creates 50 fictional login events. Each record contains:
   - `Timestamp` — a random time on 2024-06-01 between 08:00 and 08:00+24h
   - `Username` — randomly chosen from 8 fictional names (alice, bob, charlie, diana, eve, frank, grace, hank)
   - `IP Address` — randomly chosen from a pool of 8 fictional IP addresses
   - `Status` — randomly chosen as `"Success"` (75% probability) or `"Failed"` (25% probability)

2. **Deterministic seed records (18 rows):** Three fixed groups are appended to guarantee all three test cases are always present:

   | IP Address | Failures added | Total failures | Expected result |
   |---|---|---|---|
   | `10.99.0.1` | 3 | 3 | **Not flagged** — below threshold |
   | `45.33.32.156` | 6 | 6+ | **Medium Risk** — flagged in alerts |
   | `185.220.101.5` | 9 | 9+ | **High Risk** — flagged in alerts |

**Total dataset size: ~68 records** (50 random + 18 seed).

---

## 6. Detection Logic

```
Rule:
  Count records where Status = "Failed", grouped by IP Address.
  If failed_attempts >= 5  →  flag the IP as suspicious.

Risk Classification:
  failed_attempts < 5   →  not flagged (no alert)
  5 ≤ failed_attempts ≤ 8  →  Medium Risk
  failed_attempts ≥ 9   →  High Risk
```

**Important:** `"Suspicious"` is a **detection outcome**, not a raw login status. The Login Activity Log contains only `Success` and `Failed` values.

---

## 7. Project Structure

```
CyberShield/
│
├── app.py                              ← Main application (run this)
├── KumariShambhavi_CyberShield.py      ← Submission copy (identical to app.py)
├── requirements.txt                    ← Python package dependencies
└── README.md                           ← This file
```

---

## 8. Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Steps

1. Open a terminal or command prompt.

2. Navigate to the project folder:
   ```bash
   cd CyberShield
   ```

3. (Recommended) Create and activate a virtual environment:
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS / Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

4. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

---

## 9. Running the Application

```bash
streamlit run app.py
```

Streamlit will start a local web server. Open the URL shown in your terminal (usually):

```
http://localhost:8501
```

The dashboard will open automatically in your default browser.

### Running the submission copy

```bash
streamlit run KumariShambhavi_CyberShield.py
```

Both files produce an identical result.

---

## 10. Dashboard Sections

| Section | Description |
|---|---|
| **Overview** | Four metric cards: Total Logins, Successful Logins, Failed Logins, Suspicious IPs Detected |
| **Security Analytics** | Two bar charts: Login Outcome Summary and Failed Attempts per IP |
| **Security Alerts** | Alert cards for every flagged IP with risk level badge, usernames, failure count, and reason |
| **Login Activity Log** | Full colour-coded login table (green = Success, red = Failed) |
| **Sidebar Filters** | Filter the log by Login Result; filter alerts by Risk Level |

---

## 11. Test Cases

The dataset is designed to demonstrate all three detection scenarios:

| Test | IP Address | Failed Attempts | Expected Result |
|---|---|---|---|
| **Test 1** | `10.99.0.1` | 3 | **Not in Security Alerts** (below threshold) |
| **Test 2** | `45.33.32.156` | 6 | **In Security Alerts — Medium Risk** |
| **Test 3** | `185.220.101.5` | 9 | **In Security Alerts — High Risk** |

To verify Test 1: open the Failed Attempts per IP chart and confirm `10.99.0.1` has a bar of height 3, and scroll through Security Alerts to confirm it is **not** listed.

---

## 12. Limitations

- This is a simulated project for educational purposes only.
- The detection rule is intentionally simple (threshold-based); it does not use machine learning or statistical models.
- No real login data, user accounts, or network infrastructure is involved.
- The dashboard is read-only; it does not write data or send alerts to external systems.

---

## 13. License

This project is submitted as part of the IBM SkillsBuild Cyber Security 2026 programme conducted by BharatCares. It is intended for educational use only.
