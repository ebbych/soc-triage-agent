"""Command-line entry point.

    python -m agent.main samples/alert_001_guardduty_c2.json --mock
    python -m agent.main samples/alert_001_guardduty_c2.json            # real Claude (needs ANTHROPIC_API_KEY)
"""
import argparse
import json
import sys
import textwrap
import time
from pathlib import Path

from .agent import triage
from .backends import AnthropicBackend, MockBackend
from .guardrails import approve_all, deny_all, interactive_approver


TOOL_LABELS = {
    "lookup_ip_reputation": ("Checking IP reputation", "ip"),
    "lookup_domain_reputation": ("Checking domain reputation", "domain"),
    "get_asset_info": ("Looking up asset", "hostname"),
    "get_user_info": ("Looking up user", "username"),
    "search_related_events": ("Searching related events for", "entity"),
}


def make_progress_printer(stream=sys.stderr):
    """Live status lines. Printed to stderr so --json output on stdout stays clean."""
    start = time.monotonic()

    def say(text: str) -> None:
        print(f"  [{time.monotonic() - start:5.1f}s] {text}", file=stream, flush=True)

    def progress(kind: str, d: dict) -> None:
        if kind == "start":
            print(f"\nTriaging {d['alert_id']}: {d['title']}", file=stream, flush=True)
        elif kind == "injection":
            say(f"GUARDRAIL: possible prompt injection in {', '.join(d['fields'])} ({d['where']})")
        elif kind == "thinking":
            say(f"Step {d['step']}: agent is thinking...")
        elif kind == "tool":
            label, key = TOOL_LABELS.get(d["name"], (d["name"], None))
            say(f"{label} {d['args'].get(key, '') if key else d['args']}".rstrip())
        elif kind == "action_request":
            what = f"'{d['title']}'" if d["action"] == "create_ticket" and d.get("title") else d.get("target")
            say(f"Requesting action: {d['action']} -> {what}")
        elif kind == "action_result":
            say(f"  -> {d['status'].upper()}")
        elif kind == "verdict":
            note = f" (agent said {d['original']}, overridden by guardrail)" if d["original"] != d["verdict"] else ""
            say(f"Verdict submitted: {d['verdict']} at {d['confidence']:.2f} confidence{note}")
        elif kind == "stopped":
            say(f"STOPPED: {d['reason']}")

    return progress


def print_report(r: dict) -> None:
    bar = "=" * 70
    print(f"\n{bar}\nAlert {r['alert_id']}: {r['title']}\n{bar}")
    print(f"Verdict:    {r['verdict'].upper()}  (confidence {r['confidence']:.2f})")
    print(f"MITRE:      {', '.join(r['mitre_techniques']) or '-'}")
    print(f"Status:     {r['status']} in {r['steps']} step(s)")
    print("Summary:")
    print(textwrap.indent(textwrap.fill(r["summary"], 66), "  "))
    if r["actions"]:
        print("Actions:")
        for a in r["actions"]:
            what = f"ticket '{a['title']}'" if a.get("action") == "create_ticket" and a.get("title") \
                else f"{a.get('action')} -> {a.get('target')}"
            print(f"  - {what}: {a['status'].upper()}. {a['message']}")
    if r["overrides"] or r["injection_findings"] or r["guardrail_events"]:
        print("Guardrails triggered:")
        for f in r["injection_findings"]:
            print(f"  - Prompt injection detected in {f['field']}: \"{f['match']}\"")
        for o in r["overrides"]:
            print(f"  - Verdict override: {o}")
        others = [e for e in r["guardrail_events"]
                  if e not in ("guardrail.injection_detected", "guardrail.verdict_override")]
        for e in others:
            print(f"  - {e.removeprefix('guardrail.')}")
    print(f"Audit log:  {r['audit_log']}\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AI SOC alert triage agent")
    parser.add_argument("alert", help="Path to an alert JSON file")
    parser.add_argument("--mock", action="store_true", help="Use the offline rule-based model (no API key)")
    parser.add_argument("--approve", choices=["ask", "all", "none"], default="ask",
                        help="How to answer approval requests for high-risk actions (default: ask)")
    parser.add_argument("--json", action="store_true", help="Print the raw result as JSON")
    parser.add_argument("--quiet", action="store_true", help="Hide the live progress lines")
    args = parser.parse_args(argv)

    alert = json.loads(Path(args.alert).read_text(encoding="utf-8"))
    backend = MockBackend(alert) if args.mock else AnthropicBackend()
    approver = {"ask": interactive_approver, "all": approve_all, "none": deny_all}[args.approve]
    progress = None if args.quiet else make_progress_printer()

    result = triage(alert, backend, approver, progress=progress)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
