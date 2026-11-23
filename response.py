"""
response.py - automated firewall response (Phase 6)
====================================================
When enforcement is enabled, an IP is temporarily blocked when its current
risk score reaches AUTO_BLOCK_THRESHOLD from risk.py.

Safety features:
    * Dry-run by default; --enforce is required for real firewall changes.
    * Positive block duration; blocks expire and are reaped periodically.
    * Loopback, unspecified, multicast, local and allowlisted addresses are
      protected.
    * Only rules this process successfully inserts are removed on cleanup.
    * Existing identical DROP rules are recorded as pre-existing and are
      never claimed or deleted by this monitor.
    * IP addresses are validated and commands are passed as argument lists,
      never through a shell.

WARNING:
    Score-only automatic blocking is appropriate only for an isolated lab or
    a tightly monitored pilot until source attribution and false-positive
    behaviour have been validated. A risk score does not prove ownership of
    the source IP. Shared NAT/VPN/proxy addresses can represent many users.

CLI:
    python3 response.py --list
    sudo python3 response.py --unblock 192.0.2.10
    sudo python3 response.py --unblock-all
"""

import argparse
from contextlib import closing
import ipaddress
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime

from risk import AUTO_BLOCK_THRESHOLD


# ---------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------
# Add management/admin source addresses or networks here before enabling
# enforcement on a network where those addresses must never be blocked.
ALLOWLIST = []

DEFAULT_DURATION = 600       # 10 minutes
REAPER_INTERVAL = 15         # maximum normal expiry-check interval
PREEXISTING_RULE_NOTE = "pre-existing rule; not owned by monitor"


# ---------------------------------------------------------------------
# LOCAL ADDRESS DISCOVERY
# ---------------------------------------------------------------------
def local_addresses():
    """Return IPv4 addresses configured on this machine."""
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return set()

    found = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            try:
                found.add(parts[parts.index("inet") + 1].split("/")[0])
            except (ValueError, IndexError):
                continue
    return found


# ---------------------------------------------------------------------
# RESPONSE MANAGER
# ---------------------------------------------------------------------
class ResponseManager:
    def __init__(
        self,
        db_path,
        enforce=False,
        duration=DEFAULT_DURATION,
        threshold=AUTO_BLOCK_THRESHOLD,
        allowlist=None,
    ):
        if not isinstance(duration, int) or duration <= 0:
            raise ValueError("duration must be a positive integer number of seconds")
        if not isinstance(threshold, (int, float)) or not 0 <= threshold <= 100:
            raise ValueError("threshold must be between 0 and 100")

        self.db_path = db_path
        self.enforce = bool(enforce)
        self.duration = duration
        self.threshold = threshold

        networks = ALLOWLIST if allowlist is None else allowlist
        self.allow_nets = [
            ipaddress.ip_network(value, strict=False) for value in networks
        ]

        self.lock = threading.Lock()
        self.refused_until = {}
        self._init_table()

    # -----------------------------------------------------------------
    # DATABASE
    # -----------------------------------------------------------------
    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def _init_table(self):
        with closing(self._connect()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    command TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    note TEXT
                )
            """)
            conn.commit()

    def _record(self, ip, score, mode, status, command, note=None):
        with closing(self._connect()) as conn:
            conn.execute(
                """INSERT INTO blocks
                   (created, ip, score, mode, status, command, expires_at, note)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(timespec="seconds"),
                    ip,
                    int(round(score)),
                    mode,
                    status,
                    " ".join(command),
                    time.time() + self.duration,
                    note,
                ),
            )
            conn.commit()

    def _has_active(self, ip):
        with closing(self._connect()) as conn:
            row = conn.execute(
                """SELECT 1 FROM blocks
                   WHERE ip = ? AND status = 'active' AND expires_at > ?
                   LIMIT 1""",
                (ip, time.time()),
            ).fetchone()
        return row is not None

    def _set_status(self, row_id, status, note=None):
        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE blocks SET status = ?, note = COALESCE(?, note) WHERE id = ?",
                (status, note, row_id),
            )
            conn.commit()

    # -----------------------------------------------------------------
    # ADDRESS PROTECTION
    # -----------------------------------------------------------------
    def protected_reason(self, addr):
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            return "loopback/unspecified/multicast address"
        if str(addr) in local_addresses():
            return "this machine's own address"
        for network in self.allow_nets:
            if addr.version == network.version and addr in network:
                return f"allowlisted ({network})"
        return None

    # -----------------------------------------------------------------
    # FIREWALL COMMANDS
    # -----------------------------------------------------------------
    @staticmethod
    def _run(command):
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    # -----------------------------------------------------------------
    # SCORE-BASED RESPONSE
    # -----------------------------------------------------------------
    def evaluate(self, ip, score, rules=None):
        """Temporarily block an IP when score >= configured threshold.

        ``rules`` is accepted for compatibility with monitor.py. This
        score-only policy does not treat it as source authentication.
        """
        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            print(f"[RESPONSE] REFUSED {ip}: invalid risk score {score!r}")
            return

        if numeric_score < self.threshold:
            return

        # Validate and canonicalize before checking database state.
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            print(f"[RESPONSE] REFUSED: {ip!r} is not a valid IP address")
            return

        if addr.version != 4:
            print(f"[RESPONSE] SKIPPED {addr}: only IPv4 blocking is implemented")
            return

        ip = str(addr)
        reason = self.protected_reason(addr)
        if reason:
            if time.time() >= self.refused_until.get(ip, 0):
                print(f"[RESPONSE] REFUSED to block {ip}: {reason}")
                self.refused_until[ip] = time.time() + self.duration
            return

        with self.lock:
            if self._has_active(ip):
                return
            self._block(ip, numeric_score)

    # -----------------------------------------------------------------
    # BLOCK IMPLEMENTATION
    # -----------------------------------------------------------------
    def _block(self, ip, score):
        add_cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]

        if not self.enforce:
            self._record(ip, score, "dry-run", "active", add_cmd)
            print(
                f"[RESPONSE] DRY-RUN: would block {ip} for {self.duration}s "
                f"(score {score:g}; threshold {self.threshold:g})"
            )
            return

        if not shutil.which("iptables"):
            self._record(
                ip, score, "enforced", "failed", add_cmd,
                "iptables executable not found",
            )
            print("[RESPONSE] FAILED: iptables is not installed or not in PATH")
            return

        try:
            check = self._run(check_cmd)
            if check.returncode not in (0, 1):
                note = (check.stderr or "").strip()[:200] or "iptables check failed"
                self._record(ip, score, "enforced", "failed", add_cmd, note)
                print(f"[RESPONSE] FAILED checking existing rule for {ip}: {note}")
                return

            if check.returncode == 0:
                # This process did not insert the pre-existing rule, so it
                # must not delete it during cleanup.
                self._record(
                    ip, score, "enforced", "pre-existing", add_cmd,
                    PREEXISTING_RULE_NOTE,
                )
                print(
                    f"[RESPONSE] Existing DROP rule for {ip}; "
                    "recorded but not claimed or removed"
                )
                return

            result = self._run(add_cmd)
            if result.returncode != 0:
                note = (result.stderr or "").strip()[:200] or "iptables insertion failed"
                self._record(ip, score, "enforced", "failed", add_cmd, note)
                print(f"[RESPONSE] FAILED to block {ip}: {note}")
                return

        except Exception as exc:
            self._record(
                ip, score, "enforced", "failed", add_cmd, type(exc).__name__
            )
            print(f"[RESPONSE] FAILED to block {ip}: {type(exc).__name__}: {exc}")
            return

        # Only record active ownership after this process successfully added it.
        self._record(ip, score, "enforced", "active", add_cmd)
        print(
            f"[RESPONSE] BLOCKED {ip} for {self.duration}s "
            f"(risk score {score:g}, threshold {self.threshold:g})"
        )

    # -----------------------------------------------------------------
    # RELEASE / CLEANUP
    # -----------------------------------------------------------------
    def _release_row(self, row_id, ip, mode, final_status, note=None):
        """Remove only an enforced rule owned by this monitor."""
        if mode == "enforced" and note != PREEXISTING_RULE_NOTE:
            try:
                result = self._run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                )
                if result.returncode != 0:
                    detail = (result.stderr or "").strip()[:200] or "delete failed"
                    self._set_status(row_id, "release-failed", detail)
                    print(
                        f"[RESPONSE] Could not remove the monitor-owned rule for {ip}: "
                        f"{detail}. Check with: sudo iptables -S INPUT"
                    )
                    return
            except Exception as exc:
                self._set_status(row_id, "release-failed", type(exc).__name__)
                print(f"[RESPONSE] Cleanup error for {ip}: {type(exc).__name__}")
                return

        self._set_status(row_id, final_status)
        if note == PREEXISTING_RULE_NOTE:
            print(f"[RESPONSE] LEFT UNCHANGED {ip}: rule was pre-existing")
        else:
            print(f"[RESPONSE] {ip}: {final_status}")

    def _active_rows(self, only_expired, ip=None):
        sql = """SELECT id, ip, mode, COALESCE(note, '')
                 FROM blocks WHERE status = 'active'"""
        args = []
        if only_expired:
            sql += " AND expires_at <= ?"
            args.append(time.time())
        if ip is not None:
            sql += " AND ip = ?"
            args.append(ip)
        with closing(self._connect()) as conn:
            return conn.execute(sql, args).fetchall()

    def release_expired(self):
        with self.lock:
            for row_id, ip, mode, note in self._active_rows(only_expired=True):
                self._release_row(row_id, ip, mode, "expired", note)

    def unblock(self, ip=None):
        """Release one IP's active records, or all active records."""
        with self.lock:
            rows = self._active_rows(only_expired=False, ip=ip)
            for row_id, row_ip, mode, note in rows:
                self._release_row(row_id, row_ip, mode, "released", note)
            return len(rows)

    def reaper(self, stop_event):
        """Periodically release expired blocks."""
        while not stop_event.wait(REAPER_INTERVAL):
            self.release_expired()


# ---------------------------------------------------------------------
# COMMAND-LINE MANAGEMENT
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Inspect and remove firewall block records"
    )
    parser.add_argument("--db", default="monitor.db")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="show recent block records")
    group.add_argument("--unblock", metavar="IP", help="release one IP now")
    group.add_argument("--unblock-all", action="store_true", help="release all active blocks")
    args = parser.parse_args()

    manager = ResponseManager(args.db)

    if args.list:
        with closing(manager._connect()) as conn:
            rows = conn.execute(
                """SELECT id, created, ip, score, mode, status, expires_at,
                          COALESCE(note, '')
                   FROM blocks ORDER BY id DESC LIMIT 30"""
            ).fetchall()
        if not rows:
            print("No blocks recorded.")
        for rid, created, ip, score, mode, status, expires_at, note in rows:
            until = datetime.fromtimestamp(expires_at).strftime("%H:%M:%S")
            print(
                f"#{rid:<3} {created} {ip:<15} score {score:<3} "
                f"{mode:<8} {status:<14} until {until} {note}"
            )
    elif args.unblock:
        print(f"Processed {manager.unblock(args.unblock)} active record(s) for {args.unblock}")
    else:
        print(f"Processed {manager.unblock()} active record(s)")


if __name__ == "__main__":
    main()
