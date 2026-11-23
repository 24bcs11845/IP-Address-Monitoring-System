"""
dashboard.py - live web dashboard (Phase 5)
============================================
A small Flask app that READS monitor.db (it never writes to it) and shows:

    * summary cards   - total alerts, unique IPs, high-risk IPs, last alert
    * risk ranking    - every alerted IP, scored 0-100, highest first
    * recent alerts   - the latest 50 alerts as they arrive

The page polls /api/data every 3 seconds, so no manual refresh is needed.

Run it (in a SECOND terminal, no sudo needed):
    python3 dashboard.py
Then open  http://127.0.0.1:5000  in a browser on the same machine.

To open it from your host PC instead, run:
    python3 dashboard.py --host 0.0.0.0
There is no login, so only do that on the isolated host-only network.

SECURITY NOTE (worth saying in the viva)
----------------------------------------
Alert descriptions contain text an ATTACKER controls: the username they
tried to log in with comes straight from auth.log. If the page inserted
that text as HTML, an attacker could log in as a username containing a
<script> tag and run code in the administrator's browser. This is stored
XSS via log injection. The page defends against it by writing every
dynamic value with textContent, which treats it as plain text only.
"""

import argparse
import ipaddress
import os
import sqlite3
import time
from datetime import datetime

from flask import Flask, Response, jsonify

from risk import HIGH_THRESHOLD, MEDIUM_THRESHOLD, risk_table

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "monitor.db")
RECENT_LIMIT = 50
HEARTBEAT_LIMIT = 75        # seconds; capture sessions are 30 s, so this allows two missed

app = Flask(__name__)


# ---------------------------------------------------------------------
# DATA
# ---------------------------------------------------------------------
def origin_text(ip, row):
    """Human-readable location for the ranking table.
    threat_intel.py does not cache private addresses, so a missing row for a
    non-public IP is normal and is labelled here rather than shown as a gap."""
    try:
        if not ipaddress.ip_address(ip).is_global:
            return "Private / LAN"
    except ValueError:
        return "Invalid address"
    if row is None:
        return "Not looked up"
    country, city = row[2], row[3]
    place = ", ".join(x for x in (city, country) if x)
    return place or "Unknown"


def block_view(created, ip, score, mode, status, expires_at):
    """Turn a stored block record into what the page shows."""
    if status == "active" and expires_at <= time.time():
        status = "expired"                     # monitor stopped before releasing it
    if status == "active":
        label = "BLOCKED" if mode == "enforced" else "WOULD BLOCK"
    else:
        label = status.replace("-", " ").upper()
    return {
        "time": created, "ip": ip, "score": score,
        "mode": "Enforced" if mode == "enforced" else "Dry-run",
        "label": label, "active": status == "active",
        "until": datetime.fromtimestamp(expires_at).strftime("%H:%M:%S"),
    }


def capture_view(status, last_event):
    """Is packet capture alive? Judged from the heartbeat the monitor writes."""
    if "last_heartbeat" not in status:
        return {"state": "unknown"}
    age = max(0, round(time.time() - float(status["last_heartbeat"])))
    return {
        "state": "ok" if age <= HEARTBEAT_LIMIT else "stale",
        "age": age,
        "packets": int(status.get("packets_seen", status.get("tcp_packets", 0))),
        "restarts": int(status.get("restarts", 0)),
        "last_event": (f"{last_event[0]}  {last_event[1]}  {last_event[2] or ''}".strip()
                       if last_event else None),
    }


def collect():
    empty = {
        "summary": {"alerts": 0, "ips": 0, "high": 0, "last_alert": None},
        "ranking": [], "recent": [], "blocks": [], "error": None,
        "capture": {"state": "unknown"},
    }
    if not os.path.exists(DB_PATH):
        empty["error"] = "monitor.db not found - start monitor.py first."
        return empty

    conn = sqlite3.connect(DB_PATH)
    try:
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        recent_rows = conn.execute(
            "SELECT timestamp, source_ip, rule_id, severity, description "
            "FROM alerts ORDER BY id DESC LIMIT ?", (RECENT_LIMIT,)
        ).fetchall()
        try:
            intel = {r[0]: r for r in conn.execute(
                "SELECT ip, scope, country, city, asn, abuse_score FROM ip_intel")}
        except sqlite3.OperationalError:
            intel = {}
        try:
            block_rows = conn.execute(
                "SELECT created, ip, score, mode, status, expires_at "
                "FROM blocks ORDER BY id DESC LIMIT 20").fetchall()
        except sqlite3.OperationalError:       # response layer never started
            block_rows = []
        try:
            status = dict(conn.execute("SELECT key, value FROM status").fetchall())
            last_event = conn.execute(
                "SELECT timestamp, kind, detail FROM events "
                "WHERE kind IN ('capture-error', 'stall-detected', 'monitor-stopped') "
                "ORDER BY id DESC LIMIT 1").fetchone()
        except sqlite3.OperationalError:       # monitor predates health logging
            status, last_event = {}, None
    except sqlite3.Error as exc:
        empty["error"] = f"Database error: {exc}"
        return empty
    finally:
        conn.close()

    ranking = []
    for r in risk_table(DB_PATH):
        info = intel.get(r["ip"])
        ranking.append({
            "ip": r["ip"],
            "score": r["score"],
            "level": r["level"],
            "rules": r["rules"],
            "reputation": r["reputation"],
            "origin": origin_text(r["ip"], info),
            "asn": (info[4] if info and info[4] else "-"),
            "abuse": (info[5] if info and info[5] is not None else None),
        })

    return {
        "summary": {
            "alerts": total,
            "ips": len(ranking),
            "high": sum(1 for x in ranking if x["level"] == "HIGH"),
            "last_alert": recent_rows[0][0] if recent_rows else None,
        },
        "ranking": ranking,
        "capture": capture_view(status, last_event),
        "blocks": [block_view(*row) for row in block_rows],
        "recent": [
            {"time": t, "ip": ip, "rule": rule, "severity": sev, "description": desc}
            for t, ip, rule, sev, desc in recent_rows
        ],
        "error": None,
    }


@app.route("/api/data")
def api_data():
    data = collect()
    data["updated"] = datetime.now().strftime("%H:%M:%S")
    data["thresholds"] = {"medium": MEDIUM_THRESHOLD, "high": HIGH_THRESHOLD}
    return jsonify(data)


# ---------------------------------------------------------------------
# PAGE  (plain string, not a template; all dynamic text uses textContent)
# ---------------------------------------------------------------------
PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Monitoring System - Dashboard</title>
<style>
  :root {
    --bg: #0a1128; --panel: #13294b; --panel2: #1b2a4a; --line: #2a3d63;
    --text: #e8eef9; --muted: #8fa3c0; --cyan: #00e5ff;
    --low: #3ddc97; --medium: #ffb84d; --high: #ff4b5c;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font-family: Calibri, "Segoe UI", Arial, sans-serif; }
  header { display: flex; justify-content: space-between; align-items: baseline;
           padding: 18px 28px; border-bottom: 1px solid var(--line); }
  h1 { margin: 0; font-size: 20px; letter-spacing: .5px; }
  h1 span { color: var(--cyan); }
  #status { font-size: 13px; color: var(--muted); }
  #status.bad { color: var(--high); }
  main { padding: 22px 28px 40px; max-width: 1200px; margin: 0 auto; }
  #error { display: none; background: #4a1822; border: 1px solid var(--high);
           padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 22px; }
  .card { background: var(--panel); border-radius: 8px; padding: 16px 18px; }
  .card .num { font-size: 30px; font-weight: 700; color: var(--cyan); }
  .card .num.small { font-size: 17px; padding-top: 10px; }
  .card .lbl { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }
  h2 { font-size: 14px; text-transform: uppercase; letter-spacing: 1.5px;
       color: var(--muted); margin: 26px 0 10px; }
  .wrap { background: var(--panel); border-radius: 8px; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { text-align: left; padding: 10px 14px; color: var(--muted); font-weight: 600;
       border-bottom: 1px solid var(--line); font-size: 12px; text-transform: uppercase; }
  td { padding: 10px 14px; border-bottom: 1px solid var(--line); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .ip { font-family: Consolas, monospace; }
  .muted { color: var(--muted); }
  .empty { padding: 22px 14px; color: var(--muted); text-align: center; }
  .scorebox { display: flex; align-items: center; gap: 10px; min-width: 170px; }
  .bar { flex: 1; height: 8px; background: var(--panel2); border-radius: 4px; overflow: hidden; }
  .fill { height: 100%; border-radius: 4px; }
  .badge { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 10px; color: #0a1128; }
  .LOW { background: var(--low); } .MEDIUM { background: var(--medium); } .HIGH { background: var(--high); }
  .sev-High, .sev-Critical { color: var(--high); font-weight: 700; }
  .capture { padding: 9px 28px; font-size: 13px; color: var(--muted); border-bottom: 1px solid var(--line); }
  .capture.ok { color: var(--low); }
  .capture.bad { color: var(--high); font-weight: 700; background: #2a1420; }
  .capture small { display: block; color: var(--muted); font-weight: 400; margin-top: 2px; }
  .st-active { color: var(--high); font-weight: 700; }
  .st-done { color: var(--muted); }
  @media (max-width: 800px) { .cards { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
<header>
  <h1><span>&#9679;</span> IP Monitoring System <span class="muted">/ Live Dashboard</span></h1>
  <div id="status">connecting...</div>
</header>
<div id="capture" class="capture">checking capture status...</div>
<main>
  <div id="error"></div>

  <div class="cards">
    <div class="card"><div class="num" id="c-alerts">0</div><div class="lbl">Total alerts</div></div>
    <div class="card"><div class="num" id="c-ips">0</div><div class="lbl">Unique source IPs</div></div>
    <div class="card"><div class="num" id="c-high">0</div><div class="lbl">High-risk IPs</div></div>
    <div class="card"><div class="num small" id="c-last">-</div><div class="lbl">Last alert</div></div>
  </div>

  <h2>Risk ranking</h2>
  <div class="wrap"><table>
    <thead><tr><th>IP address</th><th>Risk score</th><th>Level</th><th>Rules fired</th>
    <th>Origin</th><th>Network (ASN)</th><th>Abuse score</th></tr></thead>
    <tbody id="ranking"></tbody>
  </table></div>

  <h2>Response actions</h2>
  <div class="wrap"><table>
    <thead><tr><th>Time</th><th>IP address</th><th>Score</th><th>Mode</th><th>Status</th><th>Until</th></tr></thead>
    <tbody id="blocks"></tbody>
  </table></div>

  <h2>Recent alerts</h2>
  <div class="wrap"><table>
    <thead><tr><th>Time</th><th>IP address</th><th>Rule</th><th>Severity</th><th>Description</th></tr></thead>
    <tbody id="recent"></tbody>
  </table></div>
</main>

<script>
// Every dynamic value goes through textContent, never innerHTML, so text
// supplied by an attacker (e.g. a login username) can never become markup.
function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function emptyRow(tbody, cols, message) {
  const tr = document.createElement('tr');
  const td = el('td', message, 'empty'); td.colSpan = cols;
  tr.appendChild(td); tbody.appendChild(tr);
}
const COLORS = { LOW: 'var(--low)', MEDIUM: 'var(--medium)', HIGH: 'var(--high)' };

function render(d) {
  const err = document.getElementById('error');
  if (d.error) { err.style.display = 'block'; err.textContent = d.error; }
  else { err.style.display = 'none'; }

  document.getElementById('c-alerts').textContent = d.summary.alerts;
  document.getElementById('c-ips').textContent = d.summary.ips;
  document.getElementById('c-high').textContent = d.summary.high;
  document.getElementById('c-last').textContent = d.summary.last_alert ? d.summary.last_alert.replace('T', ' ') : '-';

  const cap = document.getElementById('capture'); clear(cap);
  const c = d.capture;
  if (c.state === 'ok') {
    cap.className = 'capture ok';
    cap.appendChild(document.createTextNode('Capture healthy - heartbeat ' + c.age + 's ago, ' +
      c.packets + ' packets seen, ' + c.restarts + ' restart(s)'));
  } else if (c.state === 'stale') {
    cap.className = 'capture bad';
    cap.appendChild(document.createTextNode('CAPTURE STALLED - no heartbeat for ' + c.age +
      's. The monitor is stopped, frozen or blind.'));
  } else {
    cap.className = 'capture';
    cap.appendChild(document.createTextNode('No monitor heartbeat recorded yet.'));
  }
  if (c.last_event) cap.appendChild(el('small', 'last health event: ' + c.last_event));

  const rk = document.getElementById('ranking'); clear(rk);
  if (!d.ranking.length) emptyRow(rk, 7, 'No alerts yet - waiting for activity.');
  d.ranking.forEach(r => {
    const tr = document.createElement('tr');
    tr.appendChild(el('td', r.ip, 'ip'));

    const sc = document.createElement('td');
    const box = el('div', null, 'scorebox');
    box.appendChild(el('strong', r.score));
    const bar = el('div', null, 'bar'); const fill = el('div', null, 'fill');
    fill.style.width = Math.max(0, Math.min(100, r.score)) + '%';
    fill.style.background = COLORS[r.level] || COLORS.LOW;
    bar.appendChild(fill); box.appendChild(bar); sc.appendChild(box); tr.appendChild(sc);

    const lv = document.createElement('td');
    lv.appendChild(el('span', r.level, 'badge ' + (COLORS[r.level] ? r.level : 'LOW')));
    tr.appendChild(lv);

    const rules = Object.entries(r.rules).map(([k, v]) => k + ' (' + v + ')').join(', ');
    tr.appendChild(el('td', rules || '-'));
    tr.appendChild(el('td', r.origin));
    tr.appendChild(el('td', r.asn, 'muted'));
    tr.appendChild(el('td', r.abuse === null ? '-' : r.abuse + '/100'));
    rk.appendChild(tr);
  });

  const bl = document.getElementById('blocks'); clear(bl);
  if (!d.blocks.length) emptyRow(bl, 6, 'No blocks recorded. A high score also needs an eligible source-trustworthy rule.');
  d.blocks.forEach(b => {
    const tr = document.createElement('tr');
    tr.appendChild(el('td', String(b.time).replace('T', ' '), 'muted'));
    tr.appendChild(el('td', b.ip, 'ip'));
    tr.appendChild(el('td', b.score));
    tr.appendChild(el('td', b.mode));
    tr.appendChild(el('td', b.label, b.active ? 'st-active' : 'st-done'));
    tr.appendChild(el('td', b.until, 'muted'));
    bl.appendChild(tr);
  });

  const rc = document.getElementById('recent'); clear(rc);
  if (!d.recent.length) emptyRow(rc, 5, 'No alerts yet.');
  d.recent.forEach(a => {
    const tr = document.createElement('tr');
    tr.appendChild(el('td', String(a.time).replace('T', ' '), 'muted'));
    tr.appendChild(el('td', a.ip, 'ip'));
    tr.appendChild(el('td', a.rule));
    tr.appendChild(el('td', a.severity, 'sev-' + String(a.severity).replace(/[^A-Za-z]/g, '')));
    tr.appendChild(el('td', a.description));
    rc.appendChild(tr);
  });
}

async function refresh() {
  const status = document.getElementById('status');
  try {
    const resp = await fetch('/api/data', { cache: 'no-store' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const d = await resp.json();
    render(d);
    status.className = ''; status.textContent = 'live - updated ' + d.updated;
  } catch (e) {
    status.className = 'bad'; status.textContent = 'connection lost - retrying';
  }
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IP Monitoring dashboard")
    parser.add_argument("--host", default="127.0.0.1",
                        help="127.0.0.1 = this machine only (default); 0.0.0.0 = whole network")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--db", default=DB_PATH, help="path to monitor.db")
    args = parser.parse_args()

    DB_PATH = args.db
    print(f"Dashboard: http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}")
    print(f"Reading  : {DB_PATH}")
    app.run(host=args.host, port=args.port, debug=False)
