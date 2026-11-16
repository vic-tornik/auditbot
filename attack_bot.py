"""Incident triage for an existing Discord AuditBot ledger."""
import argparse
from collections import Counter, deque
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys

from discord_checkpoint import CheckpointError, fetch_checkpoint, message_link


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
INVITE_ACTIONS = {
    "HIJACKED": ("CRITICAL", "Remove the link from public listings and review its destination."),
    "DEAD": ("CRITICAL", "Check official listings and replace the expired or revoked invite."),
    "TWIN": ("HIGH", "Review the lookalike invite and confirm the official link."),
    "TEMPORARY": ("MEDIUM", "Review the expiration of the published invite."),
    "LOWERCASE": ("MEDIUM", "Review the invite watchdog finding and confirm the intended code."),
}


class LedgerError(ValueError):
    pass


@dataclass(frozen=True)
class Anchor:
    entry: int
    prefix: str

    @classmethod
    def parse(cls, message):
        match = re.fullmatch(
            r"(?:🔏 )?ledger anchor · n=([1-9][0-9]{0,18}) · head=([0-9a-f]{16})",
            message.strip(),
        )
        if not match or int(match[1]) > 2**63 - 1:
            raise argparse.ArgumentTypeError("expected an AuditBot ledger anchor message")
        return cls(int(match[1]), match[2])


@dataclass(frozen=True)
class Incident:
    entry: int
    time: str
    severity: str
    category: str
    action: str


def classify(kind, data):
    if kind == "leak":
        return "HIGH", "Possible credential exposure", "Review the sentinel alert privately and rotate the credential if confirmed."
    if kind == "alert":
        severity = data.get("sev")
        if severity not in SEVERITIES:
            raise LedgerError("unrecognized alert severity")
        return severity, "Discord audit alert", "Review the matching audit log event and confirm the change with its owner."
    if kind == "invite_state":
        state = data.get("to")
        if state in ("SAFE", "VANITY"):
            return None
        if state == "ERROR":
            return "INFO", "Invite check unavailable", "Check watchdog access and retry verification."
        if not isinstance(state, str) or state not in INVITE_ACTIONS:
            raise LedgerError("unrecognized invite state")
        severity, action = INVITE_ACTIONS[state]
        return severity, f"Invite state {state}", action
    if kind == "vanity" and data.get("event") in ("lost", "tier_drop"):
        return "HIGH", "Vanity invite changed", "Check the current vanity URL and update official listings if needed."
    return None


def entry_hash(previous, guild, number, timestamp, kind, body):
    fields = [previous, guild, number, timestamp, kind, body]
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


def build_report(db, guild, limit, anchor=None):
    rows = db.execute(
        "SELECT n, ts, kind, payload, prev, hash FROM ledger WHERE guild_id=? ORDER BY n", (guild,)
    )
    recent = deque(maxlen=limit)
    counts = Counter()
    previous = "GENESIS"
    entries = 0
    for number, timestamp, kind, body, parent, recorded_hash in rows:
        if number != entries + 1 or parent != previous:
            raise LedgerError(f"Ledger sequence or previous hash mismatch at entry {entries + 1}.")
        if not all(isinstance(field, str) for field in (timestamp, kind, body, recorded_hash)):
            raise LedgerError(f"Invalid ledger fields at entry {number}.")
        if entry_hash(previous, guild, number, timestamp, kind, body) != recorded_hash:
            raise LedgerError(f"Ledger hash mismatch at entry {number}.")
        if anchor and number == anchor.entry and not recorded_hash.startswith(anchor.prefix):
            raise LedgerError(f"External anchor disagrees with ledger entry {number}.")
        try:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError()
            parsed = datetime.fromisoformat(timestamp)
            if parsed.utcoffset() is None:
                raise ValueError()
            utc = parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
            decision = classify(kind, data)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise LedgerError(f"Invalid event data at entry {number}.") from exc
        if decision:
            severity, category, action = decision
            counts[severity] += 1
            recent.append(Incident(number, utc, severity, category, action))
        entries, previous = number, recorded_hash
    if anchor and entries < anchor.entry:
        raise LedgerError(f"Ledger ends at entry {entries}, before external anchor {anchor.entry}.")
    if not entries:
        raise LedgerError("No ledger entries found for this guild.")
    return {
        "guild_id": str(guild), "entries_checked": entries, "incident_events": sum(counts.values()),
        "anchor_verified_through": anchor.entry if anchor else None,
        "by_severity": {s: counts[s] for s in SEVERITIES},
        "recent": [asdict(item) for item in reversed(recent)],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path, help="existing AuditBot SQLite database")
    parser.add_argument("--guild", required=True, type=int, help="Discord server ID (required with --db)")
    parser.add_argument("--limit", type=int, help="number of recent incident events to display (default 20)")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--anchor-link", type=message_link, help="Discord message link for a checkpoint posted by AuditBot")
    source.add_argument("--anchor", type=Anchor.parse, help="quoted checkpoint message from this guild's AuditBot audit channel")
    args = parser.parse_args(argv)
    if args.limit is None:
        args.limit = 20
    if not 1 <= args.limit <= 1000:
        parser.error("--limit must be between 1 and 1000")
    if not 0 < args.guild <= 2**63 - 1:
        parser.error("--guild must be a positive SQLite integer")
    if args.anchor_link and args.anchor_link[0] != str(args.guild):
        parser.error("--anchor-link belongs to a different guild")
    try:
        uri = args.db.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA query_only=ON")
            if args.anchor_link:
                args.anchor = Anchor.parse(fetch_checkpoint(args.anchor_link))
            report = build_report(db, args.guild, args.limit, args.anchor)
            if args.anchor_link:
                report["checkpoint_message"] = "https://discord.com/channels/" + "/".join(args.anchor_link)
    except (sqlite3.Error, OSError, LedgerError, CheckpointError, argparse.ArgumentTypeError) as exc:
        print(f"Report unavailable: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Guild {report['guild_id']} | {report['entries_checked']} ledger entries checked | "
              f"{report['incident_events']} historical incident events")
        if args.anchor:
            print(f"External anchor matched through entry {args.anchor.entry}.")
        print(" | ".join(f"{s} {n}" for s, n in report["by_severity"].items() if n))
        for item in report["recent"]:
            print(f"#{item['entry']}  {item['time']}  [{item['severity']}] {item['category']}")
            print(f"    {item['action']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
