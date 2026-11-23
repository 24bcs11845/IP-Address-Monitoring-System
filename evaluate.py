#!/usr/bin/env python3
"""
evaluate.py - measure the monitor against ground truth (run on the TARGET)
===========================================================================
Inputs : trials.csv   written by attack_runner.py on Kali (what was done, when)
         monitor.db   written by monitor.py (what the system actually flagged)
Output : results.md, results_by_trial.csv  (paste the numbers into the report)

How a trial is judged
---------------------
  Each trial owns a time window: from its start to its end plus --grace seconds.
  Only alerts from the attacker's IP inside that window count.

    attack trial   PASS (detected)  if the expected rule fired in the window
                   FAIL (missed)    otherwise
    negative trial PASS (quiet)     if NOTHING fired from the attacker
                   FAIL (false alarm) if anything fired

  Latency = time of the first matching alert minus trial start.
  Alert times are stored to the whole second, so latency is accurate to
  about +/- 1 second plus any clock offset error between the two VMs.

Usage:
    python3 evaluate.py trials.csv
"""

import argparse
import csv
import re
import sqlite3
import statistics
from datetime import datetime


def load_trials(path):
    meta, body = {}, []
    with open(path, newline="") as f:
        for line in f:
            if line.startswith("#"):
                key, _, value = line[1:].strip().partition("=")
                meta[key.strip()] = value.strip()
            else:
                body.append(line)
    trials = []
    for row in csv.DictReader(body):
        trials.append({
            "trial": int(row["trial"]), "name": row["name"], "expected": row["expected"],
            "start": float(row["start"]), "end": float(row["end"]),
            "command": row["command"], "note": row["note"],
        })
    return meta, trials


def load_alerts(db_path):
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT timestamp, source_ip, rule_id FROM alerts ORDER BY id").fetchall()
    conn.close()
    return [{"t": datetime.fromisoformat(ts).timestamp(), "ip": ip, "rule": rule}
            for ts, ip, rule in rows]


CAPTURE_DEPENDENT = (
    "scan_", "repeat_conn", "evade_scan", "syn_flood", "icmp_flood",
    "xmas_scan", "null_scan", "syn_burst", "ping_normal",
)  # all these types depend on packet capture; SSH login trials use auth.log
SESSION_SLACK = 35                              # one capture session plus restart time


def load_events(db_path):
    """Health events logged by the monitor, or None if this database has none."""
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT timestamp, kind, detail FROM events ORDER BY id").fetchall()
        conn.close()
    except sqlite3.OperationalError:
        return None
    return [{"t": datetime.fromisoformat(ts).timestamp(), "kind": k, "detail": d or ""}
            for ts, k, d in rows]


def capture_incidents(events, trials):
    """Events that mean packet capture may have been blind, with the trials they touch."""
    if not trials:
        return []
    run_lo = min(t["start"] for t in trials) - 5
    run_hi = max(t["end"] for t in trials) + 60
    incidents = []
    for i, ev in enumerate(events):
        if not (run_lo <= ev["t"] <= run_hi):
            continue
        if ev["kind"] == "capture-error":
            lo, hi = ev["t"] - 5, ev["t"] + SESSION_SLACK
        elif ev["kind"] == "stall-detected":
            m = re.search(r"paused ~(\d+)s", ev["detail"])
            lo, hi = ev["t"] - (int(m.group(1)) if m else 60) - 5, ev["t"] + SESSION_SLACK
        elif ev["kind"] == "monitor-stopped":
            restart = next((x["t"] for x in events[i + 1:] if x["kind"] == "monitor-started"), run_hi)
            lo, hi = ev["t"] - 1, restart + SESSION_SLACK
        else:
            continue
        hit = [t["trial"] for t in trials if t["name"].startswith(CAPTURE_DEPENDENT)
               and t["start"] - 1 <= hi and t["end"] + 30 >= lo]
        incidents.append({**ev, "trials": hit})
    return incidents


EVASION_PREFIX = "evade_"

# The shortest a real run of each trial type can plausibly take. A far shorter run means the
# attack tool failed immediately (target unreachable, connection refused), not that the
# monitor failed to see it - e.g. a "3 failed logins" trial that lasts 0.09 s never logged in.
MIN_DURATION = {
    "brute_force": 20, "typo_logins": 3, "repeat_conn": 1.5,
    "evade_scan": 60, "evade_brute": 60,
    "syn_flood": 0.5, "icmp_flood": 2.0,
    "xmas_scan": 0.2, "null_scan": 0.2,
    "syn_burst": 1.5, "ping_normal": 8.0,
}


def run_window(trials, grace):
    """Time span of this run. Alerts outside it belong to some other run and are ignored."""
    return (min(t["start"] for t in trials) - 5, max(t["end"] for t in trials) + grace + 60)


def judge(trials, alerts, attacker, grace):
    results, claimed = [], set()
    for t in trials:
        lo, hi = t["start"] - 1.0, t["end"] + grace
        inside = [(i, a) for i, a in enumerate(alerts) if lo <= a["t"] <= hi]
        mine = [a for i, a in inside if a["ip"] == attacker]
        claimed.update(i for i, a in inside if a["ip"] == attacker)

        if t["expected"] == "none":
            passed, latency, matches = len(mine) == 0, None, 0
            outcome = "quiet" if passed else "FALSE ALARM"
        else:
            hits = [a for a in mine if a["rule"] == t["expected"]]
            passed = bool(hits)
            latency = max(0.0, min(a["t"] for a in hits) - t["start"]) if hits else None
            outcome = "detected" if passed else "MISSED"
            matches = len(hits)
        results.append({**t, "passed": passed, "outcome": outcome, "latency": latency, "matches": matches,
                        "rules_seen": ",".join(sorted({a["rule"] for a in mine})) or "-"})
    if not trials:
        return results, []
    lo, hi = run_window(trials, grace)
    unexplained = [a for i, a in enumerate(alerts) if i not in claimed and lo <= a["t"] <= hi]
    return results, unexplained


def latency_cells(values):
    if not values:
        return "-", "-", "-", "-"
    return (f"{min(values):.1f}", f"{statistics.median(values):.1f}",
            f"{statistics.mean(values):.1f}", f"{max(values):.1f}")


def build_report(meta, results, alerts, unexplained, attacker, health=None, grace=30.0):
    evasion = [r for r in results if r["name"].startswith(EVASION_PREFIX)]
    attacks = [r for r in results if r["expected"] != "none" and not r["name"].startswith(EVASION_PREFIX)]
    negatives = [r for r in results if r["expected"] == "none"]
    detected = [r for r in attacks if r["passed"]]
    false_alarms = [r for r in negatives if not r["passed"]]

    out = ["# Evaluation results", ""]
    out.append(f"- Attacker IP: `{attacker}`   Target: `{meta.get('target', '?')}`")
    out.append(f"- Clock offset applied: {meta.get('offset', '?')} s (round trip {meta.get('rtt', '?')} s)")
    if results:
        w_lo, w_hi = run_window(results, grace)
        run_alerts = [a for a in alerts if w_lo <= a["t"] <= w_hi]
    else:
        run_alerts = []
    ignored = len(alerts) - len(run_alerts)
    out.append(f"- Trials: {len(results)} ({len(attacks)} attack, {len(negatives)} negative, {len(evasion)} evasion)   "
               f"Gap between trials: {meta.get('gap', '?')} s")
    out.append(f"- Alerts in this run's time window: {len(run_alerts)}"
               + (f"   ({ignored} older/newer alerts in the database from other activity were ignored)" if ignored else ""))

    if attacks:
        out += ["", "## Detection (attack trials)", "",
                "| Trial type | Rule | Trials | Detected | Rate | Min s | Median s | Mean s | Max s |",
                "|---|---|---|---|---|---|---|---|---|"]
        for name in dict.fromkeys(r["name"] for r in attacks):
            rows = [r for r in attacks if r["name"] == name]
            ok = [r for r in rows if r["passed"]]
            lo, med, mean, hi = latency_cells([r["latency"] for r in ok])
            out.append(f"| {name} | {rows[0]['expected']} | {len(rows)} | {len(ok)} | "
                       f"{100 * len(ok) / len(rows):.0f}% | {lo} | {med} | {mean} | {hi} |")

    if negatives:
        out += ["", "## False alarms (negative trials)", "",
                "| Trial type | Trials | Quiet | False alarms | Rules that fired |",
                "|---|---|---|---|---|"]
        for name in dict.fromkeys(r["name"] for r in negatives):
            rows = [r for r in negatives if r["name"] == name]
            bad = [r for r in rows if not r["passed"]]
            fired = ",".join(sorted({r["rules_seen"] for r in bad})) or "-"
            out.append(f"| {name} | {len(rows)} | {len(rows) - len(bad)} | {len(bad)} | {fired} |")

    if evasion:
        out += ["", "## Evasion tests (known limitations, not part of the headline rate)", "",
                "These attacks were deliberately slowed to stay under the thresholds. A threshold "
                "detector is expected to miss them; \"evaded\" means the attack went unnoticed.", "",
                "| Trial type | Rule it evades | Trials | Detected | Evaded |",
                "|---|---|---|---|---|"]
        for name in dict.fromkeys(r["name"] for r in evasion):
            rows = [r for r in evasion if r["name"] == name]
            ok = [r for r in rows if r["passed"]]
            out.append(f"| {name} | {rows[0]['expected']} | {len(rows)} | {len(ok)} | {len(rows) - len(ok)} |")

    # alert-level precision: of all alerts raised, how many were the expected one for a real attack?
    expected_alerts = sum(r["matches"] for r in attacks + evasion)
    total_alerts = len(run_alerts)
    out += ["", "## Summary", ""]
    if attacks:
        out.append(f"- **Detection rate (true positive rate):** {len(detected)}/{len(attacks)} attack trials"
                   f" = {100 * len(detected) / len(attacks):.0f}%")
        out.append(f"- **Missed attacks (false negatives):** {len(attacks) - len(detected)}")
    if negatives:
        out.append(f"- **False-alarm rate:** {len(false_alarms)}/{len(negatives)} negative trials"
                   f" = {100 * len(false_alarms) / len(negatives):.0f}%")
    if evasion:
        evaded = sum(1 for r in evasion if not r["passed"])
        out.append(f"- **Evasion:** {evaded} of {len(evasion)} deliberately slowed attacks went undetected")
    if total_alerts:
        out.append(f"- **Alert precision:** {expected_alerts} of {total_alerts} alerts raised were the expected "
                   f"detection of a real attack = {100 * expected_alerts / total_alerts:.0f}%")
    out.append(f"- **Unexplained alerts** (outside any trial, or from another IP): {len(unexplained)}")
    for a in unexplained[:10]:
        out.append(f"    - {datetime.fromtimestamp(a['t']).isoformat(timespec='seconds')}  {a['ip']}  {a['rule']}")

    suspects = [r for r in results if r["name"] in MIN_DURATION
                and (r["end"] - r["start"]) < MIN_DURATION[r["name"]]]
    out += ["", "## Trial sanity checks", ""]
    if not suspects:
        out.append("- Every timed trial ran for a plausible length.")
    for r in suspects:
        out.append(f"- **Trial {r['trial']} ({r['name']}) ran for only {r['end'] - r['start']:.2f} s**; a real run "
                   f"takes at least {MIN_DURATION[r['name']]} s. The attack tool most likely failed to connect, so this "
                   "result does not measure the monitor. Rerun it.")

    if health is not None:
        out += ["", "## Capture health", ""]
        if not health["known"]:
            out.append("- **UNKNOWN.** This database has no health log, so it cannot be shown that packet "
                       "capture stayed alive. Scan results from a long unattended run are NOT trustworthy.")
        elif not health["incidents"]:
            out.append("- No capture errors, stalls or monitor restarts were logged during this run.")
        else:
            bad_trials = sorted({n for inc in health["incidents"] for n in inc["trials"]})
            for inc in health["incidents"]:
                when = datetime.fromtimestamp(inc["t"]).strftime("%H:%M:%S")
                touched = ", ".join(map(str, inc["trials"])) or "none of the capture-dependent trials"
                out.append(f"- {when}  **{inc['kind']}**  {inc['detail']}  -> affects trial(s): {touched}")
            if bad_trials:
                out.append(f"- **Trials {', '.join(map(str, bad_trials))} overlap a capture incident. Their results "
                           "do not measure detection ability (a quiet result is meaningless if the monitor was blind). "
                           "Rerun them.**")

    per_type = [sum(1 for r in attacks if r["name"] == n) for n in {r["name"] for r in attacks}] or [0]
    notes = []
    if attacks:
        notes.append(f"Each attack type was run only {min(per_type)} to {max(per_type)} times, so a rate of 100% "
                     "means \"detected in every trial run\", not \"100% accurate\".")
        if len(detected) == len(attacks):
            notes.append(f"Zero misses in {len(attacks)} trials only shows the true miss rate is probably below "
                         f"about {300 / len(attacks):.0f}% (95% confidence, the \"rule of three\"). It does not show it is zero.")
    if negatives and not false_alarms:
        notes.append(f"Zero false alarms in {len(negatives)} negative trials likewise only bounds the true "
                     f"false-alarm rate below about {300 / len(negatives):.0f}%.")
    notes.append("Alert times are stored to the whole second, so a latency under one second shows as 0.0. "
                 "Read it as \"under 1 second\", not as zero. Longer latencies are accurate to about +/- 1 second.")
    notes.append("Latency runs from the moment the attack command started, not from the first malicious packet. "
                 "For brute force it is dominated by how fast the attack tool produces failed logins.")
    notes.append("These results describe a quiet, isolated lab network and attacks the rules were designed to catch. "
                 "They say nothing about false alarms on a busy network or about attackers who adapt.")
    out += ["", "## Reading these numbers honestly", ""] + [f"- {n}" for n in notes]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Evaluate monitor.db against trials.csv")
    ap.add_argument("trials")
    ap.add_argument("--db", default="monitor.db")
    ap.add_argument("--attacker", help="attacker IP (default: read from trials.csv)")
    ap.add_argument("--grace", type=float, default=30.0,
                    help="seconds after a trial ends in which an alert still counts")
    args = ap.parse_args()

    meta, trials = load_trials(args.trials)
    attacker = args.attacker or meta.get("attacker")
    if not attacker:
        raise SystemExit("Attacker IP unknown - pass --attacker <ip>")
    alerts = load_alerts(args.db)
    results, unexplained = judge(trials, alerts, attacker, args.grace)

    events = load_events(args.db)
    health = {"known": events is not None, "incidents": capture_incidents(events or [], trials)}
    report = build_report(meta, results, alerts, unexplained, attacker, health, args.grace)
    print(report)
    with open("results.md", "w") as f:
        f.write(report)
    with open("results_by_trial.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["trial", "name", "expected", "outcome", "latency_s", "rules_seen"])
        for r in results:
            w.writerow([r["trial"], r["name"], r["expected"], r["outcome"],
                        "" if r["latency"] is None else f"{r['latency']:.1f}", r["rules_seen"]])
    print("Wrote results.md and results_by_trial.csv")


if __name__ == "__main__":
    main()
