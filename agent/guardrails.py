"""Guardrails: the controls that limit what the agent can do, even if the model is wrong or tricked.

1. Prompt-injection defense  - scan untrusted data, wrap it in tags the model is told never to obey
2. Action gate               - allowlist, target checks, critical-asset protection, human approval
3. Output validation         - verdict schema checks and policy overrides
4. Limits and kill switch    - max steps, max actions, emergency stop
(5. Audit logging lives in audit.py)
"""
import json
import os
import re
from typing import Callable

from .config import KILL_SWITCH_FILE, MIN_CONFIDENCE

# ---------------------------------------------------------------------------
# 1. Prompt-injection defense
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
        r"disregard (all |any )?(the )?(previous|prior|above|earlier)",
        r"\byou are now\b",
        r"(system|developer|admin) (note|prompt|message|override)",
        r"note to (the )?(ai|llm|assistant|agent|ai security analyst)",
        r"mark (this|the) (alert|event|finding|incident) as (a )?(false positive|benign|closed|resolved)",
        r"do not (escalate|report|alert|notify)",
        r"</?\s*untrusted",  # attempt to break out of the data wrapper
    ]
]


def _walk_strings(obj, path="$"):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from _walk_strings(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _walk_strings(value, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def scan_for_injection(obj) -> list[dict]:
    """Return one finding per string field that looks like it is trying to instruct an AI."""
    findings = []
    for path, text in _walk_strings(obj):
        for pattern in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append({"field": path, "pattern": pattern.pattern, "match": match.group(0)[:120]})
                break
    return findings


def wrap_untrusted(label: str, data) -> str:
    """Wrap attacker-influenced data in tags. The system prompt tells the model never to follow
    instructions inside these tags. Any attempt to forge the tags is neutralised first."""
    text = data if isinstance(data, str) else json.dumps(data, indent=2, default=str)
    text = re.sub(r"(?i)<\s*/?\s*untrusted", "[tag-removed]", text)
    return f"<untrusted_{label}>\n{text}\n</untrusted_{label}>"


# ---------------------------------------------------------------------------
# 2. Action gate
# ---------------------------------------------------------------------------
ACTION_RISK = {
    "create_ticket": "low",    # runs automatically
    "block_ip": "high",        # needs human approval
    "isolate_host": "high",
    "disable_user": "high",
}
# Which alert entity list an action's target must come from (None = free text, e.g. a ticket title).
ACTION_ENTITY = {"create_ticket": None, "block_ip": "ips", "isolate_host": "hosts", "disable_user": "users"}

Approver = Callable[[str, str, str], bool]


def interactive_approver(action: str, target: str, reason: str) -> bool:
    print("\n" + "!" * 64)
    print(f"  APPROVAL NEEDED: {action} -> {target}")
    print(f"  Agent's reason:  {reason}")
    print("!" * 64)
    try:
        answer = input("  Approve? [y/N]: ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def deny_all(action: str, target: str, reason: str) -> bool:
    return False


def approve_all(action: str, target: str, reason: str) -> bool:
    return True


class ActionGate:
    """Every action the agent requests passes through here. Nothing is executed for real in v1:
    approved actions are logged as DRY RUN so you can wire real integrations in later."""

    def __init__(self, alert: dict, assets: dict, users: dict, approver: Approver, audit, max_actions: int):
        self.entities = alert.get("entities", {}) or {}
        self.default_ticket_title = f"[{alert.get('alert_id', 'unknown')}] {alert.get('title', 'Security alert')}"
        self.assets = assets
        self.users = users
        self.approver = approver
        self.audit = audit
        self.max_actions = max_actions
        self.count = 0
        self.seen: set[tuple[str, str]] = set()

    def _deny(self, status: str, action, target, message: str) -> dict:
        self.audit.log(f"guardrail.{status}", action=action, target=target, message=message)
        return {"status": status, "executed": False, "message": message}

    def evaluate(self, args: dict) -> dict:
        action = args.get("action")
        target = str(args.get("target", "")).strip()
        reason = str(args.get("reason", "")).strip()

        if action not in ACTION_RISK:
            return self._deny("action_blocked", action, target,
                              f"'{action}' is not an allowed action. Allowed: {', '.join(ACTION_RISK)}.")
        if action == "create_ticket":
            return self._create_ticket(args, target, reason)
        if not target:
            return self._deny("action_blocked", action, target, "A target is required.")
        if (action, target) in self.seen:
            return self._deny("duplicate_action", action, target, "This action was already requested. Do not retry it.")
        if self.count >= self.max_actions:
            return self._deny("action_limit", action, target,
                              f"Action limit of {self.max_actions} per alert reached. Escalate to a human instead.")

        entity_key = ACTION_ENTITY[action]
        if entity_key:
            allowed = set(self.entities.get(entity_key, []))
            if target not in allowed:
                return self._deny("target_not_in_alert", action, target,
                                  f"'{target}' is not one of the alert's {entity_key}. Actions may only target "
                                  f"entities in the alert: {sorted(allowed) or 'none'}.")
            inventory = self.users if entity_key == "users" else self.assets
            if inventory.get(target, {}).get("criticality") == "critical":
                return self._deny("critical_asset_protected", action, target,
                                  f"{target} is a critical asset. Automated {action} is never allowed on it. "
                                  "Escalate to a human analyst.")

        self.seen.add((action, target))
        self.count += 1

        self.audit.log("action.approval_requested", action=action, target=target, reason=reason)
        if self.approver(action, target, reason):
            self.audit.log("action.approved", action=action, target=target, dry_run=True)
            return {"status": "approved", "executed": True, "dry_run": True,
                    "message": f"Approved by a human analyst. DRY RUN: would {action} '{target}'."}
        return self._deny("approval_denied", action, target,
                          "A human analyst did not approve this action. Do not retry it; note it in your summary.")

    def _create_ticket(self, args: dict, target: str, reason: str) -> dict:
        """Low risk, so it runs without approval. One ticket per alert; a clear title is always set."""
        title = " ".join(str(args.get("title", "")).split())[:150] or self.default_ticket_title
        if ("create_ticket", "ticket") in self.seen:
            return self._deny("duplicate_action", "create_ticket", title,
                              "A ticket already exists for this alert. Do not create another.")
        if self.count >= self.max_actions:
            return self._deny("action_limit", "create_ticket", title,
                              f"Action limit of {self.max_actions} per alert reached. Escalate to a human instead.")
        self.seen.add(("create_ticket", "ticket"))
        self.count += 1
        self.audit.log("action.executed", action="create_ticket", title=title, related_entity=target,
                       reason=reason, dry_run=True)
        return {"status": "executed", "executed": True, "dry_run": True, "title": title,
                "message": f"DRY RUN: ticket '{title}' created automatically (low risk)."}


# ---------------------------------------------------------------------------
# 3. Output validation
# ---------------------------------------------------------------------------
VERDICTS = ("true_positive", "false_positive", "needs_human")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate_verdict(args: dict, injection_findings: list, min_confidence: float = MIN_CONFIDENCE):
    """Return (final_verdict, overrides, errors). If errors is non-empty the model must try again."""
    errors = []
    verdict = args.get("verdict")
    confidence = args.get("confidence")
    techniques = args.get("mitre_techniques", [])
    summary = args.get("summary", "")

    if verdict not in VERDICTS:
        errors.append(f"verdict must be one of {VERDICTS}")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        errors.append("confidence must be a number between 0 and 1")
    if not isinstance(techniques, list) or any(not isinstance(t, str) or not MITRE_RE.match(t) for t in techniques):
        errors.append("mitre_techniques must be a list of ATT&CK IDs like T1071 or T1071.004")
    if not isinstance(summary, str) or not summary.strip():
        errors.append("summary is required")
    elif len(summary) > 4000:
        errors.append("summary must be under 4000 characters")
    if errors:
        return None, [], errors

    final = {"verdict": verdict, "confidence": float(confidence),
             "mitre_techniques": techniques, "summary": summary.strip()}
    overrides = []
    if injection_findings and verdict == "false_positive":
        final["verdict"] = "needs_human"
        overrides.append("Prompt-injection text was found in the data, so the agent is not allowed to close this "
                         "alert as a false positive. Escalated to a human.")
    elif confidence < min_confidence and verdict != "needs_human":
        final["verdict"] = "needs_human"
        overrides.append(f"Confidence {confidence:.2f} is below the {min_confidence:.2f} threshold. "
                         "Escalated to a human.")
    return final, overrides, []


# ---------------------------------------------------------------------------
# 4. Kill switch
# ---------------------------------------------------------------------------
def kill_switch_engaged() -> bool:
    return os.getenv("TRIAGE_KILL_SWITCH") == "1" or KILL_SWITCH_FILE.exists()
