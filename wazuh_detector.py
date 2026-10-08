#!/usr/bin/env python3
"""
Wazuh + ML Brute Force Detector (Dual Method)
Method 1: Trained ML model (network-flow-based)
Method 2: Behavioral analysis (SSH-log-based)
"""

import json
import joblib
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
MODEL_FILE = "bruteforce_model.pkl"
FEATURES_FILE = "feature_names.pkl"

# Brute force threshold: 3+ failed attempts from same IP
FAILED_THRESHOLD = 3

print("=" * 60)
print("   WAZUH ML-POWERED BRUTE FORCE DETECTOR")
print("=" * 60)

# ---- Load trained model ----
print("\n[1] Loading trained ML model...")
model = joblib.load(MODEL_FILE)
feature_names = joblib.load(FEATURES_FILE)
print(f"    Random Forest model loaded ({len(feature_names)} features).")

# ---- Read SSH events ----
print("\n[2] Reading SSH authentication events from Wazuh...")
ssh_events = []
with open(ALERTS_FILE, 'r', errors='ignore') as f:
    for line in f:
        try:
            alert = json.loads(line)
        except:
            continue
        groups = alert.get('rule', {}).get('groups', [])
        if 'sshd' in groups or 'authentication_failed' in groups or 'authentication_success' in groups:
            data = alert.get('data', {})
            ssh_events.append({
                'srcip': data.get('srcip', 'unknown'),
                'is_failure': 1 if 'authentication_failed' in groups else 0
            })

df = pd.DataFrame(ssh_events)
print(f"    Found {len(df)} SSH authentication events.")

if df.empty:
    print("    No SSH events found. Run SSH logins on Kali first.")
    exit()

# ---- Build per-IP behavioral features ----
print("\n[3] Analyzing behavior per source IP...")
results = []
for srcip, group in df.groupby('srcip'):
    total = len(group)
    failed = int(group['is_failure'].sum())
    success = total - failed
    failure_ratio = failed / total if total > 0 else 0

    # Method 1: ML model (map SSH data to network features)
    feature_row = {
        'packets_per_second': total,
        'avg_packet_size': 100,
        'src_ip_frequency': total,
        'byte_ratio': failed / (success + 1),
        'packet_ratio': total / (success + 1),
        'is_short_connection': 1 if failed > 0 else 0,
        'bidirectional_duration_ms': total * 500,
        'bidirectional_packets': total * 6,
        'bidirectional_bytes': total * 600,
        'protocol': 6
    }
    X = pd.DataFrame([feature_row])[feature_names]
    ml_prediction = int(model.predict(X)[0])

    # Method 2: Behavioral rule (SSH-specific, accurate)
    behavioral_detection = 1 if failed >= FAILED_THRESHOLD else 0

    results.append({
        'srcip': srcip,
        'total': total,
        'failed': failed,
        'success': success,
        'failure_ratio': failure_ratio,
        'ml_prediction': ml_prediction,
        'behavioral_detection': behavioral_detection
    })

# ---- Report ----
print("\n[4] DETECTION RESULTS")
print("=" * 60)
print(f"{'Source IP':<18}{'Attempts':<10}{'Failed':<8}{'ML Model':<12}{'Behavioral':<12}")
print("-" * 60)

attack_ips = []
for r in results:
    ml_str = "ATTACK" if r['ml_prediction'] == 1 else "Normal"
    beh_str = "ATTACK" if r['behavioral_detection'] == 1 else "Normal"
    print(f"{r['srcip']:<18}{r['total']:<10}{r['failed']:<8}{ml_str:<12}{beh_str:<12}")
    if r['behavioral_detection'] == 1 or r['ml_prediction'] == 1:
        attack_ips.append(r)

print("=" * 60)

# ---- Final alerts ----
if attack_ips:
    print("\n  *** BRUTE FORCE ALERTS ***")
    for r in attack_ips:
        print(f"  [!] IP {r['srcip']} - {r['failed']} failed attempts "
              f"({r['failure_ratio']:.0%} failure rate)")
    print(f"\n  Total sources flagged: {len(attack_ips)}")
else:
    print("\n  No brute force attacks detected.")
print()