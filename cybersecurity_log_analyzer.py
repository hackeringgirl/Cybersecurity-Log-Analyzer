"""
Cybersecurity Log Analyzer
============================
Parses and analyzes system security logs to detect
suspicious activities, brute force attacks, and anomalies.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import re
import warnings
warnings.filterwarnings('ignore')

# ── 1. GENERATE REALISTIC SECURITY LOGS ──────────────────────────────────────

np.random.seed(42)

def random_ip(malicious=False):
    if malicious:
        malicious_ips = ['185.220.101.45', '45.33.32.156', '198.51.100.23',
                         '192.0.2.1', '203.0.113.99', '185.220.100.240']
        return np.random.choice(malicious_ips)
    return f"{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}"

def random_user(failed=False):
    legit_users = ['alice', 'bob', 'charlie', 'diana', 'admin', 'sysadmin']
    fake_users = ['root', 'administrator', 'guest', 'test', 'oracle', 'postgres', 'admin123']
    return np.random.choice(fake_users if failed else legit_users)

start_time = datetime(2024, 11, 1, 0, 0, 0)
logs = []

for i in range(5000):
    timestamp = start_time + timedelta(seconds=np.random.randint(0, 86400 * 30))
    event_type = np.random.choice(
        ['SUCCESSFUL_LOGIN', 'FAILED_LOGIN', 'SUDO_COMMAND', 'PORT_SCAN', 'FILE_ACCESS', 'SSH_DISCONNECT'],
        p=[0.30, 0.35, 0.10, 0.10, 0.10, 0.05]
    )

    is_malicious = event_type in ['FAILED_LOGIN', 'PORT_SCAN'] and np.random.random() < 0.4
    ip = random_ip(malicious=is_malicious)
    user = random_user(failed=(event_type == 'FAILED_LOGIN'))
    port = np.random.choice([22, 80, 443, 3306, 5432, 8080, 21, 23])

    logs.append({
        'timestamp': timestamp,
        'event_type': event_type,
        'source_ip': ip,
        'username': user,
        'port': port,
        'status': 'FAILURE' if 'FAILED' in event_type else 'SUCCESS',
        'is_malicious_ip': int(is_malicious)
    })

df = pd.DataFrame(logs).sort_values('timestamp').reset_index(drop=True)
df['hour'] = df['timestamp'].dt.hour
df['day'] = df['timestamp'].dt.day_name()
df['date'] = df['timestamp'].dt.date

df.to_csv('security_logs.csv', index=False)
print("✅ Security log generated:", df.shape)
print("\nEvent Distribution:")
print(df['event_type'].value_counts())

# ── 2. THREAT ANALYSIS ────────────────────────────────────────────────────────

# 2a. Brute Force Detection: IPs with many failed logins
failed_logins = df[df['event_type'] == 'FAILED_LOGIN']
ip_fails = failed_logins.groupby('source_ip')['event_type'].count().sort_values(ascending=False)
brute_force_threshold = 20
brute_force_ips = ip_fails[ip_fails >= brute_force_threshold]

print(f"\n🚨 Brute Force IPs detected (≥{brute_force_threshold} failed logins): {len(brute_force_ips)}")
print(brute_force_ips.head())

# 2b. Port scan detection
port_scans = df[df['event_type'] == 'PORT_SCAN']
scan_ips = port_scans.groupby('source_ip')['port'].nunique().sort_values(ascending=False)
scanner_ips = scan_ips[scan_ips >= 3]
print(f"\n🔍 Port Scanners detected (≥3 different ports): {len(scanner_ips)}")

# 2c. Suspicious off-hours activity (2AM - 5AM)
off_hours = df[(df['hour'] >= 2) & (df['hour'] <= 5) & (df['event_type'] == 'FAILED_LOGIN')]
print(f"\n🌙 Suspicious off-hours login attempts: {len(off_hours)}")

# ── 3. VISUALIZATIONS ────────────────────────────────────────────────────────

fig, axes = plt.subplots(2, 2, figsize=(16, 10))
fig.suptitle('Cybersecurity Log Analyzer Dashboard', fontsize=16, fontweight='bold')

# 3a. Event Type Distribution
event_counts = df['event_type'].value_counts()
colors = ['#4CAF50', '#F44336', '#FF9800', '#9C27B0', '#2196F3', '#607D8B']
axes[0, 0].barh(event_counts.index[::-1], event_counts.values[::-1], color=colors[::-1], alpha=0.85)
axes[0, 0].set_title('Security Event Distribution')
axes[0, 0].set_xlabel('Event Count')

# 3b. Login attempts by hour (heatmap-style)
hourly_fails = df[df['event_type'] == 'FAILED_LOGIN'].groupby('hour').size()
axes[0, 1].bar(hourly_fails.index, hourly_fails.values,
               color=['#F44336' if 2 <= h <= 5 else '#2196F3' for h in hourly_fails.index],
               alpha=0.85)
axes[0, 1].set_title('Failed Login Attempts by Hour of Day\n(Red = Off-hours suspicious zone)')
axes[0, 1].set_xlabel('Hour (24h)')
axes[0, 1].set_ylabel('Failed Logins')
axes[0, 1].axvspan(2, 5, alpha=0.1, color='red', label='Suspicious hours')
axes[0, 1].legend()

# 3c. Top Attacking IPs
top_attackers = ip_fails.head(10)
bars = axes[1, 0].barh(top_attackers.index[::-1], top_attackers.values[::-1],
                       color='#F44336', alpha=0.85)
axes[1, 0].set_title('Top 10 IPs by Failed Login Count')
axes[1, 0].set_xlabel('Failed Login Attempts')
axes[1, 0].axvline(x=brute_force_threshold, color='orange', linestyle='--',
                   linewidth=2, label=f'Brute Force Threshold ({brute_force_threshold})')
axes[1, 0].legend()

# 3d. Daily login activity
daily_events = df.groupby(['date', 'status']).size().unstack(fill_value=0)
if 'SUCCESS' in daily_events.columns:
    axes[1, 1].plot(range(len(daily_events)), daily_events['SUCCESS'], color='#4CAF50', label='Success', linewidth=2)
if 'FAILURE' in daily_events.columns:
    axes[1, 1].plot(range(len(daily_events)), daily_events['FAILURE'], color='#F44336', label='Failure', linewidth=2)
axes[1, 1].set_title('Daily Login Events: Success vs Failure')
axes[1, 1].set_xlabel('Day (Nov 2024)')
axes[1, 1].set_ylabel('Event Count')
axes[1, 1].legend()

plt.tight_layout()
plt.savefig('log_analyzer_dashboard.png', dpi=150, bbox_inches='tight')
print("\n✅ Dashboard saved as log_analyzer_dashboard.png")
plt.show()

# ── 4. SECURITY REPORT ────────────────────────────────────────────────────────

print("\n" + "="*60)
print("🔐 CYBERSECURITY THREAT REPORT")
print("="*60)
total = len(df)
failed = len(df[df['status'] == 'FAILURE'])
print(f"Total Log Entries:          {total:,}")
print(f"Failed Login Attempts:      {failed:,} ({failed/total*100:.1f}%)")
print(f"Brute Force IPs:            {len(brute_force_ips)}")
print(f"Port Scanning IPs:          {len(scanner_ips)}")
print(f"Off-Hours Suspicious Events:{len(off_hours)}")
print(f"\nTop Threat IP: {ip_fails.index[0]} ({ip_fails.iloc[0]} failed attempts)")
print("\n⚠️  RECOMMENDATION: Block the brute force IPs immediately using firewall rules.")
