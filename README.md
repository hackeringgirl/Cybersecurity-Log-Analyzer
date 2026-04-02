# 📋 Cybersecurity Log Analyzer

A cybersecurity tool that parses and analyzes system security logs to detect **brute force attacks**, **port scanning**, **off-hours suspicious activity**, and other threats.

## 📌 Project Overview

Security logs are goldmines of information, but they're too large to read manually. This analyzer automatically flags threats from thousands of log entries in seconds.

## 🧠 What I Built

- Generated 5,000 realistic security log entries (SSH logins, port scans, sudo commands)
- Detected brute force attacks (IPs with ≥20 failed login attempts)
- Identified port scanners (IPs probing multiple ports)
- Flagged suspicious off-hours activity (2AM–5AM login attempts)
- Generated a comprehensive threat report

## 🔍 Threat Types Detected

| Threat | Detection Method |
|--------|-----------------|
| **Brute Force** | IP with ≥20 failed logins |
| **Port Scanning** | Single IP hitting ≥3 different ports |
| **Off-Hours Attack** | Failed logins between 2AM–5AM |
| **Credential Stuffing** | Logins with common usernames (root, admin, test) |

## 📊 Dashboard Includes

- Event type distribution (logins, port scans, file access, etc.)
- Failed login attempts by hour of day (with suspicious zone highlighted)
- Top 10 attacking IPs ranked by attempt count
- Daily success vs failure login trend

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python | Core language |
| Pandas | Log parsing & aggregation |
| NumPy | Data generation |
| Matplotlib & Seaborn | Security dashboard |
| Regex | Log pattern matching |

## 📁 Files

```
08-log-analyzer/
├── cybersecurity_log_analyzer.py    # Main analyzer script
├── security_logs.csv                # Simulated log data
├── log_analyzer_dashboard.png       # Visual dashboard
└── README.md
```

## 🚀 How to Run

```bash
pip install pandas numpy matplotlib seaborn
python cybersecurity_log_analyzer.py
```

## 📋 Sample Threat Report

```
Total Log Entries:           5,000
Failed Login Attempts:       1,742 (34.8%)
Brute Force IPs:             6
Port Scanning IPs:           4
Off-Hours Suspicious Events: 89

Top Threat IP: 185.220.101.45 (47 failed attempts)

⚠️  RECOMMENDATION: Block brute force IPs using firewall rules.
```

## 👩‍💻 Author

**hackeringgirl** — Built as part of my Data Analytics & Cybersecurity portfolio
