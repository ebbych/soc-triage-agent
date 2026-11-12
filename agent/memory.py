"""Case memory: a local SQLite record of past investigations.

After each completed run the final (post-guardrail) verdict is saved with the alert's entities. The
search_past_cases tool lets the agent ask "have we seen this host, user, IP, domain, hash or CVE before?"

Memory is a classic place to poison an AI agent, so:
- Only completed runs are saved, and only the verdict that passed the guardrails.
- Past cases are returned as untrusted data like any other tool output.
- If prompt injection was detected in a past case, its summary text is withheld.
- The system prompt tells the model that past cases are context, never proof.

    python -m agent.memory            # list recent cases
    python -m agent.memory --clear    # delete all stored cases
"""
import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import CASE_DB

ENTITY_KINDS = ("hosts", "users", "ips", "domains", "hashes", "cves")
SUMMARY_LIMIT = 400

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL, saved_at TEXT NOT NULL, source TEXT, title TEXT,
    verdict TEXT NOT NULL, confidence REAL, techniques TEXT, summary TEXT,
    injection_detected INTEGER NOT NULL DEFAULT 0, verdict_overridden INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS case_entities (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_entities_value ON case_entities(value);
"""


class CaseMemory:
    def __init__(self, path: Path | str = CASE_DB):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)

    def save(self, alert: dict, result: dict) -> int | None:
        """Store a finished investigation. Unfinished or failed runs are never remembered."""
        if result.get("status") != "completed":
            return None
        with self.db:
            cursor = self.db.execute(
                "INSERT INTO cases (alert_id, saved_at, source, title, verdict, confidence, techniques, summary,"
                " injection_detected, verdict_overridden) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(alert.get("alert_id", "unknown")), datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 str(alert.get("source", ""))[:80], str(alert.get("title", ""))[:200], result["verdict"],
                 result.get("confidence"), json.dumps(result.get("mitre_techniques", [])),
                 str(result.get("summary", ""))[:4000],
                 int(bool(result.get("injection_findings"))), int(bool(result.get("overrides")))))
            entities = alert.get("entities") or {}
            rows = {(kind, str(value).strip().lower())
                    for kind in ENTITY_KINDS for value in entities.get(kind) or [] if str(value).strip()}
            self.db.executemany("INSERT INTO case_entities (case_id, kind, value) VALUES (?, ?, ?)",
                                [(cursor.lastrowid, kind, value) for kind, value in sorted(rows)])
        return cursor.lastrowid

    def search(self, entity: str, limit: int = 5, current_alert_id: str | None = None) -> list[dict]:
        """Past cases involving an entity, newest first."""
        rows = self.db.execute(
            "SELECT DISTINCT c.* FROM cases c JOIN case_entities e ON e.case_id = c.id "
            "WHERE e.value = ? ORDER BY c.id DESC LIMIT ?",
            (entity.strip().lower(), max(1, min(int(limit), 20)))).fetchall()
        return [self._present(row, current_alert_id) for row in rows]

    def recent(self, limit: int = 20) -> list[dict]:
        rows = self.db.execute("SELECT * FROM cases ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._present(row) for row in rows]

    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM cases").fetchone()[0]

    def clear(self) -> None:
        with self.db:
            self.db.execute("DELETE FROM case_entities")
            self.db.execute("DELETE FROM cases")

    @staticmethod
    def _present(row, current_alert_id: str | None = None) -> dict:
        case = {"alert_id": row["alert_id"], "date": row["saved_at"][:10], "source": row["source"],
                "title": row["title"], "verdict": row["verdict"], "confidence": row["confidence"],
                "mitre_techniques": json.loads(row["techniques"] or "[]")}
        if row["injection_detected"]:
            case["injection_detected"] = True
            case["summary"] = "[withheld: prompt injection was detected in this case]"
        else:
            summary = row["summary"] or ""
            case["summary"] = summary[:SUMMARY_LIMIT] + ("..." if len(summary) > SUMMARY_LIMIT else "")
        if row["verdict_overridden"]:
            case["verdict_set_by_guardrail"] = True
        if current_alert_id and row["alert_id"] == current_alert_id:
            case["same_alert_as_current"] = True
        return case


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Inspect the agent's case memory")
    parser.add_argument("--clear", action="store_true", help="Delete all stored cases")
    args = parser.parse_args(argv)
    memory = CaseMemory()
    if args.clear:
        memory.clear()
        print("Case memory cleared.")
        return 0
    cases = memory.recent()
    print(f"{memory.count()} case(s) stored in {CASE_DB}")
    for c in cases:
        flag = "  [injection]" if c.get("injection_detected") else ""
        print(f"  {c['date']}  {c['verdict']:<15} {c['alert_id']:<20} {c['title'][:60]}{flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
