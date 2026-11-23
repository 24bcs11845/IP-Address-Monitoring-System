"""
risk.py - risk scoring (Phase 4)
=================================
Calculates a 0-100 risk score from the freshest alert for each rule plus
AbuseIPDB reputation. The alert classification threshold and the automatic
firewall threshold are intentionally separate.

Important:
    HIGH_THRESHOLD (75) classifies an IP as HIGH risk in the dashboard.
    AUTO_BLOCK_THRESHOLD (90) is the default response threshold.

The 90-point automatic-block threshold is a conservative starting point for
a monitored pilot, NOT a universal production standard. Calibrate it against
representative benign traffic before enabling enforcement. A numeric score
does not authenticate a source IP; forged packet sources and attribution
errors can still cause false blocks.

Show the current ranking:
    python3 risk.py
"""

import sqlite3
from datetime import datetime


# ---------------------------------------------------------------------
# TUNABLE SETTINGS
# ---------------------------------------------------------------------
WEIGHTS = {
    "R-01": 35,      # TCP SYN port scan
    "R-02": 50,      # SSH brute force from auth.log
    "R-03": 35,      # SYN flood
    "R-04": 25,      # ICMP echo-request flood
    "R-05": 30,      # unusual TCP flags
}

DEFAULT_WEIGHT = 25
REPUTATION_WEIGHT = 0.30
HALF_LIFE = 3600           # seconds; contribution halves every hour

MEDIUM_THRESHOLD = 40
HIGH_THRESHOLD = 75        # risk classification / dashboard threshold
AUTO_BLOCK_THRESHOLD = 85 # separate, more conservative response threshold

# Retained for compatibility with older monitor.py versions. It is NOT used
# by the score-only response policy in response.py. No rule here proves that
# a packet's source IP is authentic, so do not describe this set as proof of
# source trustworthiness.
SPOOF_RESISTANT = frozenset()


def level_for(score):
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def compute_risk(db_path, ip, now=None):
    """Return the risk breakdown for one IP address."""
    now = now or datetime.now()

    conn = sqlite3.connect(db_path)
    try:
        alerts = conn.execute(
            "SELECT rule_id, timestamp FROM alerts WHERE source_ip = ?", (ip,)
        ).fetchall()
        try:
            row = conn.execute(
                "SELECT abuse_score FROM ip_intel WHERE ip = ?", (ip,)
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
    finally:
        conn.close()

    # Each rule contributes once, using its freshest (least-decayed) alert.
    per_rule = {}
    for rule, stamp in alerts:
        age = max(
            0.0,
            (now - datetime.fromisoformat(stamp)).total_seconds()
        )
        value = WEIGHTS.get(rule, DEFAULT_WEIGHT) * 0.5 ** (age / HALF_LIFE)
        per_rule[rule] = max(per_rule.get(rule, 0.0), value)

    abuse = row[0] if row and row[0] is not None else 0
    reputation_part = abuse * REPUTATION_WEIGHT
    score = min(100.0, sum(per_rule.values()) + reputation_part)

    return {
        "ip": ip,
        "score": round(score),
        "level": level_for(score),
        "rules": {rule: round(value) for rule, value in sorted(per_rule.items())},
        "reputation": round(reputation_part),
    }


def risk_table(db_path, now=None):
    """Return every IP with an alert, highest risk first."""
    conn = sqlite3.connect(db_path)
    try:
        ips = [row[0] for row in conn.execute(
            "SELECT DISTINCT source_ip FROM alerts"
        )]
    finally:
        conn.close()

    table = [compute_risk(db_path, ip, now) for ip in ips]
    return sorted(table, key=lambda row: row["score"], reverse=True)


def describe_risk(result):
    """Return one readable console line."""
    parts = ", ".join(
        f"{rule} {value}" for rule, value in result["rules"].items()
    ) or "no alerts"
    line = (
        f"{result['ip']} | risk {result['score']}/100 {result['level']} | "
        f"{parts}, reputation {result['reputation']}"
    )
    if result["score"] >= AUTO_BLOCK_THRESHOLD:
        line += "  -> AUTOMATIC BLOCK THRESHOLD REACHED"
    elif result["score"] >= HIGH_THRESHOLD:
        line += "  -> HIGH RISK (below automatic block threshold)"
    return line


if __name__ == "__main__":
    for entry in risk_table("monitor.db"):
        print(describe_risk(entry))
