"""Append-only audit log. Every model turn, tool call, action and guardrail decision is recorded
as one JSON line, so a reviewer can reconstruct exactly what the agent did and why."""
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import LOG_DIR

# Never let credentials end up in logs.
_SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]+"),   # Anthropic API keys
    re.compile(r"AKIA[0-9A-Z]{16}"),          # AWS access key IDs
]


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


class AuditLog:
    def __init__(self, alert_id: str, log_dir: Path = LOG_DIR):
        self.run_id = uuid.uuid4().hex[:12]
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^A-Za-z0-9_\-]", "_", alert_id)
        self.path = log_dir / f"audit-{safe_id}-{self.run_id}.jsonl"
        self.events: list[dict] = []

    def log(self, event: str, **fields) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "event": event,
            **fields,
        }
        line = redact(json.dumps(record, default=str))
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self.events.append(record)

    def guardrail_events(self) -> list[dict]:
        return [e for e in self.events if e["event"].startswith("guardrail.")]
