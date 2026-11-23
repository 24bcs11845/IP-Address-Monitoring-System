"""
IP Address Monitoring System - Phase 6
=======================================
Phase 6 adds RESPONSE: IPs scoring 75+ are blocked at the firewall
(response.py). DRY-RUN by default; add --enforce to really block.
Phase 4 added RISK SCORING: after every alert the IP gets a 0-100 score
(risk.py). Phase 3 added ENRICHMENT: every alerted IP is looked up (country, ISP/ASN,
AbuseIPDB reputation) by threat_intel.py. Earlier phases:

  1. SQLite storage     - every alert is saved, not just printed
  2. Rule R-02 (real)   - brute-force detection from actual failed SSH
                          logins in /var/log/auth.log
  3. Alert cooldown     - the same attack can alert again later, but
                          won't spam the console while it is ongoing

Two things run at the same time:
  - Main thread  : Scapy captures TCP/ICMP       -> Rules R-01, R-03, R-04, R-05
  - Second thread: tails /var/log/auth.log       -> Rule R-02 (brute force)

HOW TO RUN (on the target VM)
-----------------------------
    sudo python3 monitor.py

Reading auth.log and sniffing packets both need root, hence sudo.
"""

import argparse
import os
import re
import signal
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, ICMP

from threat_intel import ThreatIntel, describe
from risk import compute_risk, describe_risk, AUTO_BLOCK_THRESHOLD
from response import ResponseManager, DEFAULT_DURATION, local_addresses

# ---------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------
DB_PATH = "monitor.db"

# Network interface to sniff. None = system default.
# With TWO adapters (NAT + host-only) you MUST set this to the host-only
# one, e.g. "ens37". Find it with:  ip -br addr
INTERFACE = "ens33"   # <- your host-only adapter (check with: ip -br addr)
AUTH_LOG = "/var/log/auth.log"

# R-01: port scan
PORT_SCAN_THRESHOLD = 15     # more than this many distinct ports ...
PORT_SCAN_WINDOW = 10        # ... within this many seconds

# R-03: SYN flood
SYN_FLOOD_THRESHOLD = 100   # more than this many pure SYNs ...
SYN_FLOOD_WINDOW = 5        # ... within this many seconds
SYN_FLOOD_MAX_PORTS = 5    # aimed at no more than this many destination ports

# R-04: ICMP echo-request flood
ICMP_FLOOD_THRESHOLD = 100 # more than this many echo requests ...
ICMP_FLOOD_WINDOW = 10     # ... within this many seconds

# R-05: malformed / unusual TCP flag combinations
ILLEGAL_FLAGS_THRESHOLD = 3 # 3 or more within the window
ILLEGAL_FLAGS_WINDOW = 10

# Bound memory and worst-case per-source history processing under floods.
HISTORY_CAP = 2000

# R-02: brute force
BRUTE_FORCE_THRESHOLD = 10   # more than this many failed logins ...
BRUTE_FORCE_WINDOW = 60      # ... within this many seconds

# Do not re-alert for the same (ip, rule) more often than this
ALERT_COOLDOWN = 60          # seconds

# Matches lines like:
#   Failed password for root from 192.168.56.101 port 41234 ssh2
#   Failed password for invalid user admin from 192.168.56.101 port 41234 ssh2
#
# SECURITY: the username is typed by the ATTACKER and can contain spaces or
# text resembling a source field. The greedy username group selects the
# rightmost source-field-shaped substring, and the end anchor requires it to
# be the final source field in the sshd log entry. This reduces simple parser
# spoofing; it is not treated as cryptographic proof of source attribution.
FAILED_LOGIN = re.compile(
    r"Failed password for (?:invalid user )?(.*) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+(?: ssh2)?$"
)


# ---------------------------------------------------------------------
# STORAGE
# ---------------------------------------------------------------------
db_lock = threading.Lock()   # two threads write to the DB, so guard it
intel = None                 # set in main() once the DB exists
responder = None             # set in main()
LOCAL_IPS = set()            # this machine's own addresses, filled in main()
DEBUG = False                # --debug: print how many ports each source has touched
PACKETS_SEEN = 0             # TCP and ICMP packets seen since start

# Capture runs in short sessions so a dead or stale socket is replaced quickly.
CAPTURE_SESSION = 30         # seconds per sniff() session
STALL_THRESHOLD = 20         # a session overrunning by this much means the host/VM was paused
MAX_BACKOFF = 30             # longest wait between restarts after repeated failures


def init_db():
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                source_ip   TEXT NOT NULL,
                rule_id     TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                kind      TEXT NOT NULL,
                detail    TEXT
            )
        """)
        conn.execute("CREATE TABLE IF NOT EXISTS status (key TEXT PRIMARY KEY, value TEXT)")
        conn.commit()
        conn.close()


def log_event(kind, detail=""):
    """Record something that affects whether the monitor can be trusted."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO events (timestamp, kind, detail) VALUES (?, ?, ?)",
                     (datetime.now().isoformat(timespec="seconds"), kind, detail))
        conn.commit()
        conn.close()


def save_status(restarts):
    """Heartbeat: the dashboard reads this to show whether capture is alive."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.executemany("INSERT OR REPLACE INTO status (key, value) VALUES (?, ?)", [
            ("last_heartbeat", str(time.time())),
            ("packets_seen", str(PACKETS_SEEN)),
            ("restarts", str(restarts)),
        ])
        conn.commit()
        conn.close()


def save_alert(source_ip, rule_id, severity, description):
    stamp = datetime.now().isoformat(timespec="seconds")
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO alerts (timestamp, source_ip, rule_id, severity, description) "
            "VALUES (?, ?, ?, ?, ?)",
            (stamp, source_ip, rule_id, severity, description),
        )
        conn.commit()
        conn.close()
    print(f"[ALERT] {stamp}  {severity:<8} {rule_id}  {source_ip:<15} {description}")

    # Enrichment does slow network I/O, so everything after the alert runs
    # on its own thread and never holds up packet processing.
    threading.Thread(target=post_alert, args=(source_ip,), daemon=True).start()


def post_alert(ip):
    """After an alert is saved: enrich the IP first, then score it.
    Order matters - the score uses the reputation that enrichment just cached."""
    if intel is not None:
        print(f"[INTEL]  {describe(intel.lookup(ip))}")
    result = compute_risk(DB_PATH, ip)
    print(f"[RISK]   {describe_risk(result)}")
    if responder is not None:
        responder.evaluate(ip, result["score"], rules=list(result["rules"]))


# ---------------------------------------------------------------------
# DETECTION
# ---------------------------------------------------------------------
class Detector:
    def __init__(self):
        self.port_history = defaultdict(lambda: deque(maxlen=HISTORY_CAP))
        self.login_history = defaultdict(lambda: deque(maxlen=HISTORY_CAP))
        self.syn_history = defaultdict(lambda: deque(maxlen=HISTORY_CAP))
        self.icmp_history = defaultdict(lambda: deque(maxlen=HISTORY_CAP))
        self.illegal_flag_history = defaultdict(lambda: deque(maxlen=HISTORY_CAP))
        self.last_alert = {}                      # (ip, rule) -> time of last alert
        self.debug_level = {}
        self.lock = threading.Lock()

    def _cooling(self, ip, rule, now):
        """Read-only fast path: True while this source/rule is in cooldown."""
        last = self.last_alert.get((ip, rule))
        return last is not None and now - last < ALERT_COOLDOWN

    def _cooldown_ok(self, ip, rule, now):
        """Record an alert time if this source/rule is no longer cooling."""
        if self._cooling(ip, rule, now):
            return False
        self.last_alert[(ip, rule)] = now
        return True

    @staticmethod
    def _prune(history, now, window):
        while history and now - history[0][0] > window:
            history.popleft()

    # ---- R-01: port scan -------------------------------------------
    def check_port_scan(self, ip, port, now=None):
        now = now if now is not None else time.time()
        with self.lock:
            if self._cooling(ip, "R-01", now):
                return
            history = self.port_history[ip]
            history.append((now, port))
            self._prune(history, now, PORT_SCAN_WINDOW)
            distinct = {item[1] for item in history}

            if DEBUG:
                level = len(distinct) // 5
                if level == 0:
                    self.debug_level[ip] = 0
                elif level > self.debug_level.get(ip, 0):
                    self.debug_level[ip] = level
                    print(f"[DEBUG] {ip}: {len(distinct)} distinct ports, "
                          f"{len(history)} packets in the last {PORT_SCAN_WINDOW}s")
            if len(distinct) > PORT_SCAN_THRESHOLD and self._cooldown_ok(ip, "R-01", now):
                save_alert(ip, "R-01", "High",
                           f"Port scan: {len(distinct)} distinct ports in {PORT_SCAN_WINDOW}s")

    # ---- R-02: brute force -----------------------------------------
    def check_brute_force(self, ip, username, now=None):
        now = now if now is not None else time.time()
        with self.lock:
            if self._cooling(ip, "R-02", now):
                return
            history = self.login_history[ip]
            history.append((now, username))
            self._prune(history, now, BRUTE_FORCE_WINDOW)
            if len(history) > BRUTE_FORCE_THRESHOLD and self._cooldown_ok(ip, "R-02", now):
                save_alert(ip, "R-02", "Critical",
                           f"Brute force: {len(history)} failed SSH logins in "
                           f"{BRUTE_FORCE_WINDOW}s (last user tried: {username})")

    # ---- TCP flag classification ----------------------------------
    @staticmethod
    def is_port_scan_probe(flags):
        """Accept ordinary SYN probes, including ECN SYNs, but exclude
        FIN/RST/ACK combinations so NULL/XMAS/SYN-FIN packets stay out of R-01.
        """
        flags = int(flags)
        return bool(flags & 0x02) and not bool(flags & (0x01 | 0x04 | 0x10))

    @staticmethod
    def is_pure_syn(flags):
        """R-03 counts only the pure SYN flag combination (0x02)."""
        return int(flags) == 0x02

    # ---- R-03: SYN flood -------------------------------------------
    def check_syn_flood(self, ip, port, flags, now=None):
        now = now if now is not None else time.time()
        # Count pure SYN packets only. Unusual flags belong to R-05.
        if not self.is_pure_syn(flags):
            return
        with self.lock:
            if self._cooling(ip, "R-03", now):
                return
            history = self.syn_history[ip]
            history.append((now, port))
            self._prune(history, now, SYN_FLOOD_WINDOW)
            distinct_ports = {item[1] for item in history}
            if (len(history) > SYN_FLOOD_THRESHOLD
                    and len(distinct_ports) <= SYN_FLOOD_MAX_PORTS
                    and self._cooldown_ok(ip, "R-03", now)):
                save_alert(ip, "R-03", "High",
                           f"SYN flood: {len(history)} SYNs to {len(distinct_ports)} ports "
                           f"in {SYN_FLOOD_WINDOW}s")

    # ---- R-04: ICMP echo-request flood -----------------------------
    def check_icmp_flood(self, ip, icmp_type, now=None):
        if icmp_type != 8:               # echo request only; ignore echo replies
            return
        now = now if now is not None else time.time()
        with self.lock:
            if self._cooling(ip, "R-04", now):
                return
            history = self.icmp_history[ip]
            history.append((now,))
            self._prune(history, now, ICMP_FLOOD_WINDOW)
            if len(history) > ICMP_FLOOD_THRESHOLD and self._cooldown_ok(ip, "R-04", now):
                save_alert(ip, "R-04", "Medium",
                           f"ICMP echo-request flood: {len(history)} requests "
                           f"in {ICMP_FLOOD_WINDOW}s")

    # ---- R-05: illegal TCP flags -----------------------------------
    @staticmethod
    def is_illegal_flags(flags):
        return (flags == 0 or (flags & 0x29) == 0x29 or (flags & 0x03) == 0x03)

    def check_illegal_flags(self, ip, flags, now=None):
        if not self.is_illegal_flags(flags):
            return
        now = now if now is not None else time.time()
        with self.lock:
            if self._cooling(ip, "R-05", now):
                return
            history = self.illegal_flag_history[ip]
            history.append((now, flags))
            self._prune(history, now, ILLEGAL_FLAGS_WINDOW)
            if len(history) >= ILLEGAL_FLAGS_THRESHOLD and self._cooldown_ok(ip, "R-05", now):
                save_alert(ip, "R-05", "High",
                           f"Illegal TCP flags: {len(history)} NULL/XMAS/SYN-FIN packets "
                           f"in {ILLEGAL_FLAGS_WINDOW}s")


detector = Detector()


# ---------------------------------------------------------------------
# INPUT 1: network packets (R-01, R-03, R-04, R-05)
# ---------------------------------------------------------------------
def on_packet(packet):
    global PACKETS_SEEN
    if not packet.haslayer(IP):
        return
    src = packet[IP].src
    PACKETS_SEEN += 1
    # sniff() sees both directions. Ignore our own outbound packets so replies
    # cannot make this host look like a scanner or flood source.
    if src in LOCAL_IPS:
        return

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = int(tcp.flags)

        # R-01 counts normal SYN probes only. Malformed flag combinations
        # are handled by R-05 and cannot inflate the port-scan history.
        if detector.is_port_scan_probe(flags):
            detector.check_port_scan(src, tcp.dport)

        # R-03 independently counts pure SYNs to a small port set.
        detector.check_syn_flood(src, tcp.dport, flags)

        # R-05 handles NULL, XMAS and SYN-FIN packets.
        detector.check_illegal_flags(src, flags)
    elif packet.haslayer(ICMP):
        detector.check_icmp_flood(src, int(packet[ICMP].type))


# ---------------------------------------------------------------------
# INPUT 2: auth.log (R-02)
# ---------------------------------------------------------------------
def watch_auth_log(path=AUTH_LOG, stop_event=None):
    """
    Behaves like `tail -f`: jump to the end of the file, then keep
    reading new lines as they are written. Old entries are ignored,
    so we only react to what happens while the monitor is running.
    """
    if not os.path.exists(path):
        print(f"[WARN] {path} not found - brute force detection disabled.")
        print("       Fix: sudo apt install rsyslog -y && sudo systemctl restart rsyslog")
        return

    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while not (stop_event and stop_event.is_set()):
            line = f.readline()
            if not line:
                time.sleep(0.5)       # nothing new yet, wait a moment
                continue
            match = FAILED_LOGIN.search(line)
            if match:
                username, ip = match.group(1), match.group(2)
                detector.check_brute_force(ip, username)


def install_signal_handlers(stop):
    """
    Make Ctrl+C (and `kill`) shut the monitor down cleanly, first time.

    Scapy's sniff() catches KeyboardInterrupt itself and simply returns, so
    the capture loop would see a normal return and start another session -
    Ctrl+C would have to be pressed repeatedly. Instead the handler sets the
    stop flag, then raises KeyboardInterrupt to break out of sniff(). It also
    ignores any further Ctrl+C, so an impatient second press cannot interrupt
    the firewall cleanup that follows.
    """
    def on_signal(signum, frame):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        stop.set()
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)


# ---------------------------------------------------------------------
# SUPERVISED CAPTURE
# ---------------------------------------------------------------------
def capture_loop(stop):
    """
    Run packet capture in short sessions and restart it if anything goes wrong.

    Why: a long-running sniff() can die (an exception when the network
    interface changes) or go deaf (a socket left stale after the host sleeps
    or the VM is paused), and either way the monitor would keep "running"
    while detecting nothing. Here every failure is logged, capture is
    restarted with a fresh socket, and the dashboard shows a heartbeat so
    blindness is visible. A new socket is opened every CAPTURE_SESSION
    seconds regardless, which also cures a silently stale one.

    Known limit: a few milliseconds are blind at each session boundary.
    """
    restarts = failures_in_a_row = 0
    log_event("capture-started", f"interface={INTERFACE or 'default'}")
    save_status(restarts)
    while not stop.is_set():
        began = time.time()
        errored = False
        try:
            sniff(iface=INTERFACE, prn=on_packet, filter="tcp or icmp", store=False,
                  timeout=CAPTURE_SESSION)
            failures_in_a_row = 0
        except (KeyboardInterrupt, PermissionError):
            raise
        except Exception as exc:
            errored = True
            restarts += 1
            failures_in_a_row += 1
            delay = min(MAX_BACKOFF, 3 * failures_in_a_row)
            detail = f"{type(exc).__name__}: {exc}"
            print(f"[WARN] capture error ({detail}) - restarting in {delay}s")
            log_event("capture-error", detail)
            stop.wait(delay)

        if stop.is_set():
            break
        elapsed = time.time() - began
        overrun = elapsed - CAPTURE_SESSION
        if overrun > STALL_THRESHOLD:
            msg = f"capture paused ~{overrun:.0f}s (host asleep or VM paused?)"
            print(f"[WARN] {msg}")
            log_event("stall-detected", msg)
        elif elapsed < 1.0 and not errored and not stop.is_set():
            stop.wait(1.0)          # never spin if sniff() returns instantly
        save_status(restarts)


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
def main():
    global intel, responder
    parser = argparse.ArgumentParser(description="IP monitoring system")
    parser.add_argument("--enforce", action="store_true",
                        help="really add iptables rules (default is dry-run: record only)")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help="seconds a block lasts (default %(default)s)")
    parser.add_argument("--debug", action="store_true",
                        help="print port-count milestones per source IP (for diagnosing detection)")
    args = parser.parse_args()
    global DEBUG
    DEBUG = args.debug

    init_db()
    LOCAL_IPS.update(local_addresses())
    LOCAL_IPS.add("127.0.0.1")
    intel = ThreatIntel(DB_PATH)
    responder = ResponseManager(DB_PATH, enforce=args.enforce, duration=args.duration)
    stop_reaper = threading.Event()

    print("=" * 66)
    print(" IP Monitoring System - Phase 7 (supervised capture)")
    print(" R-01 port scan   R-02 SSH brute force   R-03 SYN flood")
    print(" R-04 ICMP flood  R-05 illegal TCP flags")
    print(f" Interface: {INTERFACE or 'default'}")
    print(f" Ignoring own addresses: {', '.join(sorted(LOCAL_IPS))}")
    print(f" Database: {DB_PATH}      Ctrl+C to stop")
    if args.enforce:
        print(f" RESPONSE: ENFORCING - risk score {AUTO_BLOCK_THRESHOLD}+; "
              f"temporary blocks last {args.duration}s")
        print(" WARNING: lab/pilot score-only blocking can block innocent source IPs.")
        print(" Add management/admin addresses to response.py ALLOWLIST before enforcement.")
    else:
        print(f" RESPONSE: dry-run - automatic block threshold {AUTO_BLOCK_THRESHOLD}; "
              "firewall is NOT changed")
    print("=" * 66)

    threading.Thread(target=watch_auth_log, daemon=True).start()
    threading.Thread(target=responder.reaper, args=(stop_reaper,), daemon=True).start()

    stop_capture = threading.Event()
    install_signal_handlers(stop_capture)
    log_event("monitor-started", f"enforce={args.enforce}")
    try:
        capture_loop(stop_capture)
    except PermissionError:
        print("Permission denied. Run with: sudo python3 monitor.py")
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)     # cleanup must not be interruptible
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        print("\nStopping - removing any firewall rules, please wait...")
        stop_capture.set()
        stop_reaper.set()
        # Firewall cleanup comes FIRST and must never depend on anything that can fail
        # (such as a database write): a monitor that dies leaving a DROP rule behind
        # would lock out the very host it was meant to protect.
        try:
            released = responder.unblock()      # leave the firewall as we found it
            if released:
                print(f"Removed {released} active block(s) on exit.")
        finally:
            try:
                log_event("monitor-stopped")
            except Exception as exc:
                print(f"[WARN] could not log shutdown ({type(exc).__name__})")


if __name__ == "__main__":
    main()
