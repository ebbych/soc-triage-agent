"""Run the agent on every sample alert and score its verdicts against labels.json.

    python -m evals.run_eval           # offline mock model
    python -m evals.run_eval --live    # real Claude (needs ANTHROPIC_API_KEY)

High-risk actions are always auto-denied here, so evals never need a human at the keyboard.
"""
import argparse
import json
import sys
from pathlib import Path

from agent.agent import triage
from agent.backends import AnthropicBackend, MockBackend
from agent.guardrails import deny_all

ROOT = Path(__file__).resolve().parent.parent


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the triage agent on labeled sample alerts")
    parser.add_argument("--live", action="store_true", help="Use the real Claude API instead of the mock")
    args = parser.parse_args(argv)

    labels = json.loads((ROOT / "evals" / "labels.json").read_text(encoding="utf-8"))
    rows, passed = [], 0
    for path in sorted((ROOT / "samples").glob("*.json")):
        alert = json.loads(path.read_text(encoding="utf-8"))
        expected = labels.get(alert["alert_id"])
        if not expected:
            continue
        backend = AnthropicBackend() if args.live else MockBackend(alert)
        print(f"Running {alert['alert_id']}...", file=sys.stderr, flush=True)
        r = triage(alert, backend, deny_all)
        ok = r["verdict"] in expected
        passed += ok
        guards = sorted({e.removeprefix("guardrail.") for e in r["guardrail_events"]})
        rows.append((alert["alert_id"], "/".join(expected), r["verdict"], "PASS" if ok else "FAIL", guards))

    print(f"\n{'Alert':<20} {'Expected':<26} {'Got':<15} {'Result':<7} Guardrails triggered")
    print("-" * 110)
    for alert_id, exp, got, res, guards in rows:
        print(f"{alert_id:<20} {exp:<26} {got:<15} {res:<7} {', '.join(guards) or '-'}")
    print("-" * 110)
    print(f"Accuracy: {passed}/{len(rows)} ({passed / max(len(rows), 1):.0%})\n")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
