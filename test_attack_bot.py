"""Offline checks for the incident reporter's command-line contract."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
from tempfile import NamedTemporaryFile
import unittest
from unittest.mock import patch

from attack_bot import entry_hash, main


ANCHOR = "🔏 ledger anchor · n=3 · head=05ab0843e50d418f"


def fixture_db(db):
    db.execute("CREATE TABLE ledger (guild_id INTEGER, n INTEGER, ts TEXT, kind TEXT, payload TEXT, prev TEXT, hash TEXT)")
    events = [
        ("scan", {"count": 0}), ("leak", {"rule": "synthetic"}),
        ("invite_state", {"from": "SAFE", "to": "HIJACKED"}),
        ("invite_state", {"from": "HIJACKED", "to": "SAFE"}),
        ("alert", {"sev": "HIGH"}),
    ]
    previous = "GENESIS"
    for number, (kind, data) in enumerate(events, 1):
        ts = f"2026-01-01T00:0{number}:00+00:00"
        body = json.dumps(data, sort_keys=True, separators=(",", ":"))
        head = entry_hash(previous, 1, number, ts, kind, body)
        db.execute("INSERT INTO ledger VALUES (?,?,?,?,?,?,?)", (1, number, ts, kind, body, previous, head))
        previous = head


class ReportTests(unittest.TestCase):
    def setUp(self):
        with NamedTemporaryFile(prefix="audit #", suffix=".sqlite", delete=False) as file:
            self.path = Path(file.name)
        self.addCleanup(self.path.unlink, missing_ok=True)
        db = sqlite3.connect(self.path)
        try:
            with db:
                fixture_db(db)
        finally:
            db.close()

    def run_report(self, *options):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = main(["--db", str(self.path), "--guild", "1", *options])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def change_db(self, sql):
        db = sqlite3.connect(self.path)
        try:
            with db:
                db.execute(sql)
        finally:
            db.close()

    def test_anchor_covers_prefix_and_limit_only_affects_display(self):
        original = self.path.read_bytes()
        code, out, err = self.run_report("--anchor", ANCHOR, "--limit", "1", "--json")
        self.assertEqual((code, err), (0, ""))
        report = json.loads(out)
        self.assertEqual(report["anchor_verified_through"], 3)
        self.assertEqual(report["entries_checked"], 5)
        self.assertEqual(report["incident_events"], 3)
        self.assertEqual([i["entry"] for i in report["recent"]], [5])
        self.assertEqual(self.path.read_bytes(), original)

    def test_unanchored_mode(self):
        code, out, err = self.run_report("--json")
        self.assertEqual((code, err), (0, ""))
        self.assertIsNone(json.loads(out)["anchor_verified_through"])

    def test_live_source_drives_the_same_ledger_check(self):
        link = "https://discord.com/channels/1/2/3"
        with patch("attack_bot.fetch_checkpoint", return_value=ANCHOR) as fetch:
            code, out, err = self.run_report("--anchor-link", link, "--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["checkpoint_message"], link)
        self.assertEqual(json.loads(out)["anchor_verified_through"], 3)
        fetch.assert_called_once_with(("1", "2", "3"))

    def test_rejects_cross_guild_link_before_fetch(self):
        with patch("attack_bot.fetch_checkpoint") as fetch:
            code, out, _ = self.run_report("--anchor-link", "https://discord.com/channels/9/2/3")
        self.assertEqual((code, out), (2, ""))
        fetch.assert_not_called()

    def test_checkpoint_past_end_of_valid_chain(self):
        self.change_db("DELETE FROM ledger WHERE n >= 3")
        self.assertEqual(self.run_report("--json")[0], 0)
        code, out, err = self.run_report("--anchor", ANCHOR, "--json")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("before external anchor 3", err)

    def test_checkpoint_disagrees_with_internally_valid_chain(self):
        code, out, err = self.run_report("--anchor", ANCHOR[:-1] + "0")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("disagrees with ledger entry 3", err)

    def test_corruption_after_checkpoint_fails_whole_report(self):
        self.change_db("UPDATE ledger SET payload='private text' WHERE n=5")
        code, out, err = self.run_report("--anchor", ANCHOR, "--json")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("hash mismatch at entry 5", err)
        self.assertNotIn("private text", err)

    def test_unexpected_binary_payload_fails_cleanly(self):
        self.change_db("UPDATE ledger SET payload=x'ff' WHERE n=4")
        code, out, err = self.run_report("--json")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Invalid ledger fields at entry 4", err)

    def test_invalid_checkpoint_is_a_usage_error(self):
        for message in (ANCHOR + " extra", ANCHOR.replace("n=3", "n=0"), ANCHOR[:-1]):
            with self.subTest(message=message):
                code, out, err = self.run_report("--anchor", message)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("expected an AuditBot ledger anchor", err)

    def test_other_guilds_rows_do_not_count_toward_checkpoint(self):
        self.change_db("UPDATE ledger SET guild_id=2 WHERE n >= 3")
        code, out, err = self.run_report("--anchor", ANCHOR)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Ledger ends at entry 2", err)


if __name__ == "__main__":
    unittest.main()
