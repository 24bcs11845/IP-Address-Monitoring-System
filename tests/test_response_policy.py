import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess

from response import ResponseManager, PREEXISTING_RULE_NOTE
from risk import AUTO_BLOCK_THRESHOLD


class ResponsePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "response-test.db")
        self.manager = ResponseManager(self.db, enforce=False, duration=60)

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_auto_block_threshold_is_90(self):
        self.assertEqual(AUTO_BLOCK_THRESHOLD, 90)
        self.assertEqual(self.manager.threshold, 90)

    def test_score_below_threshold_does_not_block(self):
        with patch.object(self.manager, "_block") as block:
            self.manager.evaluate("192.0.2.10", 89)
        block.assert_not_called()

    def test_score_at_threshold_triggers_response(self):
        with patch.object(self.manager, "_block") as block:
            self.manager.evaluate("192.0.2.10", 90, rules=["R-04"])
        block.assert_called_once_with("192.0.2.10", 90.0)

    def test_dry_run_records_without_firewall_call(self):
        with patch.object(self.manager, "_run", side_effect=AssertionError("firewall called")):
            self.manager.evaluate("192.0.2.10", 90)
        with sqlite3.connect(self.db) as conn:
            row = conn.execute("SELECT mode, status FROM blocks").fetchone()
        self.assertEqual(row, ("dry-run", "active"))

    def test_preexisting_rule_is_not_claimed_or_deleted(self):
        manager = ResponseManager(self.db, enforce=True, duration=60)
        with patch("response.local_addresses", return_value=set()), \
             patch("response.shutil.which", return_value="/usr/sbin/iptables"), \
             patch.object(manager, "_run", return_value=CompletedProcess([], 0, "", "")) as run:
            manager.evaluate("192.0.2.11", 90)
            self.assertEqual(run.call_count, 1)  # check only; no insertion
            self.assertEqual(manager.unblock("192.0.2.11"), 0)
            self.assertEqual(run.call_count, 1)  # no deletion
        with sqlite3.connect(self.db) as conn:
            row = conn.execute("SELECT status, note FROM blocks").fetchone()
        self.assertEqual(row, ("pre-existing", PREEXISTING_RULE_NOTE))

    def test_owned_rule_is_inserted_and_removed(self):
        manager = ResponseManager(self.db, enforce=True, duration=60)
        responses = [
            CompletedProcess([], 1, "", ""),  # rule absent
            CompletedProcess([], 0, "", ""),  # insert succeeds
            CompletedProcess([], 0, "", ""),  # delete succeeds
        ]
        with patch("response.local_addresses", return_value=set()), \
             patch("response.shutil.which", return_value="/usr/sbin/iptables"), \
             patch.object(manager, "_run", side_effect=responses) as run:
            manager.evaluate("192.0.2.12", 90)
            self.assertEqual(manager.unblock("192.0.2.12"), 1)
        self.assertEqual(run.call_count, 3)
        with sqlite3.connect(self.db) as conn:
            row = conn.execute("SELECT status FROM blocks").fetchone()
        self.assertEqual(row, ("released",))


if __name__ == "__main__":
    unittest.main()
