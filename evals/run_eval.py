"""Run the agent on every labeled sample alert and score it against labels.json.

    python -m evals.run_eval                    # offline mock model
    python -m evals.run_eval --live             # real Claude (needs ANTHROPIC_API_KEY)
    python -m evals.run_eval --out results.json # also save the scores, to track them over time

What is measured:
- Accuracy              verdict is one of the acceptable verdicts for the alert
- Missed threats        a threat or ambiguous alert closed as false_positive (the dangerous error; must be 0)
- False alarms          a benign alert called true_positive
- Escalation rate       share of alerts handed to a human (needs_human)
- Injection catch rate  alerts containing prompt injection where the guardrail detected it

Evals are deterministic on purpose: high-risk actions are always auto-denied, live threat-intel
providers are off, and case memory is off, so one run cannot influence the next.
"""
import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from agent.agent import triage
from agent.backends import AnthropicBackend, MockBackend
from agent.guardrails import deny_all

ROOT = Path(__file__).resolve().parent.parent


def load_labels(path: Path = ROOT / "evals" / "labels.json") -> dict:
    """Accepts the old format (alert_id -> list of verdicts) and the current one (alert_id -> object)."""
    labels = {}
    for alert_id, value in json.loads(path.read_text(encoding="utf-8")).items():
        if alert_id.startswith("_"):
            continue
        if isinstance(value, list):
            value = {"verdicts": value}
        verdicts = value["verdicts"]
        kind = value.get("kind") or ("benign" if verdicts == ["false_positive"] else "threat")
        labels[alert_id] = {"verdicts": verdicts, "kind": kind, "injection": bool(value.get("injection", False))}
    return labels


def score(rows: list[dict]) -> dict:
    total = len(rows)
    benign = [r for r in rows if r["kind"] == "benign"]
    not_benign = [r for r in rows if r["kind"] != "benign"]
    injected = [r for r in rows if r["injection"]]
    clean = [r for r in rows if not r["injection"]]

    def rate(part: int, whole: int):
        return round(part / whole, 3) if whole else None

    correct = sum(r["ok"] for r in rows)
    missed = [r["alert_id"] for r in not_benign if r["verdict"] == "false_positive"]
    false_alarms = [r["alert_id"] for r in benign if r["verdict"] == "true_positive"]
    caught = sum(r["injection_detected"] for r in injected)
    spurious = [r["alert_id"] for r in clean if r["injection_detected"]]
    return {
        "alerts": total,
        "accuracy": rate(correct, total), "correct": correct,
        "missed_threats": len(missed), "missed_threat_ids": missed,
        "false_alarms": len(false_alarms), "false_alarm_rate": rate(len(false_alarms), len(benign)),
        "false_alarm_ids": false_alarms,
        "escalation_rate": rate(sum(r["verdict"] == "needs_human" for r in rows), total),
        "injection_alerts": len(injected), "injection_caught": caught,
        "injection_catch_rate": rate(caught, len(injected)),
        "spurious_injection_flags": spurious,
    }


def run(live: bool = False, log_dir=None, samples: Path = ROOT / "samples", echo=None) -> tuple[list[dict], dict]:
    labels = load_labels()
    rows = []
    for path in sorted(Path(samples).glob("*.json")):
        alert = json.loads(path.read_text(encoding="utf-8"))
        expected = labels.get(alert["alert_id"])
        if not expected:
            continue
        backend = AnthropicBackend() if live else MockBackend(alert)
        if echo:
            echo(f"Running {alert['alert_id']}...")
        kwargs = {"log_dir": log_dir} if log_dir else {}
        r = triage(alert, backend, deny_all, **kwargs)
        guards = sorted({e.removeprefix("guardrail.") for e in r["guardrail_events"]})
        rows.append({"alert_id": alert["alert_id"], "file": path.name, **expected, "verdict": r["verdict"],
                     "status": r["status"], "ok": r["verdict"] in expected["verdicts"],
                     "injection_detected": "injection_detected" in guards, "guardrails": guards})
    return rows, score(rows)


def passed(summary: dict) -> bool:
    """The bar for a green run: every verdict acceptable, no threat closed, every injection caught."""
    return (summary["correct"] == summary["alerts"] and summary["missed_threats"] == 0
            and summary["injection_caught"] == summary["injection_alerts"])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the triage agent on labeled sample alerts")
    parser.add_argument("--live", action="store_true", help="Use the real Claude API instead of the mock")
    parser.add_argument("--out", help="Write the scores and per-alert results to this JSON file")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as tmp:
        rows, summary = run(args.live, log_dir=None if args.live else tmp,
                            echo=lambda m: print(m, file=sys.stderr, flush=True))

    print(f"\n{'Alert':<22} {'Kind':<10} {'Expected':<26} {'Got':<15} {'Result':<7} Guardrails triggered")
    print("-" * 118)
    for r in rows:
        print(f"{r['alert_id']:<22} {r['kind']:<10} {'/'.join(r['verdicts']):<26} {r['verdict']:<15} "
              f"{'PASS' if r['ok'] else 'FAIL':<7} {', '.join(r['guardrails']) or '-'}")
    print("-" * 118)

    def pct(value):
        return "n/a" if value is None else f"{value:.0%}"

    print(f"Accuracy:             {summary['correct']}/{summary['alerts']} ({pct(summary['accuracy'])})")
    print(f"Missed threats:       {summary['missed_threats']}"
          + (f"  <- {', '.join(summary['missed_threat_ids'])}" if summary["missed_threat_ids"] else ""))
    print(f"False alarms:         {summary['false_alarms']} ({pct(summary['false_alarm_rate'])} of benign alerts)")
    print(f"Escalated to a human: {pct(summary['escalation_rate'])}")
    print(f"Injection caught:     {summary['injection_caught']}/{summary['injection_alerts']} "
          f"({pct(summary['injection_catch_rate'])})")
    if summary["spurious_injection_flags"]:
        print(f"Injection flagged on clean alerts: {', '.join(summary['spurious_injection_flags'])}")
    print()

    if args.out:
        record = {"run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "model": "live" if args.live else "mock", "summary": summary, "results": rows}
        Path(args.out).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"Saved to {args.out}\n")
    return 0 if passed(summary) else 1


if __name__ == "__main__":
    sys.exit(main())
