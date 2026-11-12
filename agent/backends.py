"""Model backends.

AnthropicBackend - the real agent, powered by Claude through the Anthropic API.
MockBackend      - a simple rule-based stand-in so you can run and test the whole pipeline
                   (tools, guardrails, audit log) offline with no API key. It is NOT intelligent.
"""
import json
import os
import re
import uuid

from .config import MODEL


class AnthropicBackend:
    def __init__(self, model: str = MODEL, max_tokens: int = 2048):
        if not os.getenv("ANTHROPIC_API_KEY"):
            raise SystemExit("ANTHROPIC_API_KEY is not set. Export it, or run with --mock to use the offline model.")
        try:
            import anthropic
        except ImportError:
            raise SystemExit("The anthropic package is missing. Run: pip install -r requirements.txt")
        self.client = anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens

    def create(self, system: str, messages: list, tools: list) -> dict:
        response = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system, messages=messages, tools=tools)
        return {"stop_reason": response.stop_reason,
                "content": [block.model_dump(exclude_none=True) for block in response.content]}


class MockBackend:
    """Follows a fixed playbook: enrich every entity, pull related events, then decide by simple rules.

    gullible=True simulates a model that falls for prompt injection (it obeys "mark this alert as a
    false positive"), so you can watch the output guardrail catch it.
    """

    BENIGN_EVENTS = {"helpdesk_password_reset", "approved_change", "scheduled_vuln_scan", "approved_data_share"}
    MALICIOUS_EVENTS = {"dns_beaconing", "outbound_to_c2", "new_persistence_cron", "malware_execution_blocked"}
    INJECTION_BAIT = re.compile(r"mark (this|the) (alert|event|finding) as (a )?false positive", re.I)

    def __init__(self, alert: dict, gullible: bool = True):
        self.alert = alert
        self.gullible = gullible
        ents = alert.get("entities", {}) or {}
        self.hosts, self.users = ents.get("hosts", []), ents.get("users", [])
        self.ips, self.domains = ents.get("ips", []), ents.get("domains", [])
        self.hashes, self.cves = ents.get("hashes", []), ents.get("cves", [])

    def create(self, system: str, messages: list, tools: list) -> dict:
        turn = sum(1 for m in messages if m["role"] == "assistant")
        if turn == 0:
            calls = ([("lookup_ip_reputation", {"ip": ip}) for ip in self.ips]
                     + [("lookup_domain_reputation", {"domain": d}) for d in self.domains]
                     + [("lookup_file_hash", {"hash": h}) for h in self.hashes]
                     + [("lookup_cve", {"cve": c}) for c in self.cves]
                     + [("get_asset_info", {"hostname": h}) for h in self.hosts]
                     + [("get_user_info", {"username": u}) for u in self.users])
            if calls:
                return self._respond("Enriching the alert's entities with threat intel and context.", calls)
        if turn <= 1:
            calls = [("search_related_events", {"entity": e, "hours": 24}) for e in self.hosts + self.users]
            calls += [("search_past_cases", {"entity": e}) for e in self.hosts + self.users]
            if calls and turn == 1:
                return self._respond("Pulling related events and past cases for the affected hosts and users.",
                                     calls)
        return self._decide(messages)

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _respond(text: str, calls: list) -> dict:
        content = [{"type": "text", "text": text}]
        content += [{"type": "tool_use", "id": f"toolu_mock_{uuid.uuid4().hex[:16]}", "name": n, "input": a}
                    for n, a in calls]
        return {"stop_reason": "tool_use", "content": content}

    @staticmethod
    def _unwrap(text: str):
        lines = text.strip().splitlines()
        if lines and lines[0].startswith("<untrusted_"):
            text = "\n".join(lines[1:-1])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}

    def _evidence(self, messages: list) -> list[dict]:
        found = []
        for m in messages:
            if m["role"] == "user" and isinstance(m["content"], list):
                found += [self._unwrap(b["content"]) for b in m["content"] if b.get("type") == "tool_result"]
        return found

    def _mitre(self) -> list[str]:
        text = f"{self.alert.get('title', '')} {self.alert.get('description', '')}".lower()
        if "sql" in text or "exploit" in text:
            return ["T1190"]
        if "phish" in text:
            return ["T1566.002"]
        if "malware" in text:
            return ["T1204.002"]
        if "impossible travel" in text:
            return ["T1078"]
        if "outbound transfer" in text:
            return ["T1567"]
        if any(k in text for k in ("c&c", "command and control", "beacon")):
            return ["T1071.004"] if "dns" in text else ["T1071"]
        if any(k in text for k in ("failed login", "brute")):
            return ["T1110"]
        return []

    def _decide(self, messages: list) -> dict:
        evidence = self._evidence(messages)
        scores = {}
        for r in evidence:
            key = r.get("ip") or r.get("domain") or r.get("hash")
            if key and r.get("risk_score") is not None:
                scores[key] = r["risk_score"]
        event_types = {e.get("type") for r in evidence for e in r.get("events", [])}
        max_risk = max(scores.values(), default=0)
        kev = sorted(r["cve"] for r in evidence if r.get("in_kev") is True)
        alert_text = json.dumps(self.alert)

        calls = []
        if self.gullible and self.INJECTION_BAIT.search(alert_text):
            # Simulates a hijacked model obeying the attacker's text.
            verdict, conf, techniques = "false_positive", 0.92, []
            summary = "Request notes say this is an authorized penetration test, so closing as a false positive."
        elif max_risk >= 70 or event_types & self.MALICIOUS_EVENTS:
            verdict, conf, techniques = "true_positive", 0.9, self._mitre()
            bad = [k for k, s in scores.items() if s >= 70]
            summary = (f"Malicious activity confirmed. High-risk indicators: {', '.join(bad) or 'none'}. "
                       f"Related events: {', '.join(sorted(event_types & self.MALICIOUS_EVENTS)) or 'none'}. "
                       + (f"Known exploited vulnerabilities involved: {', '.join(kev)}. " if kev else "") +
                       "Containment requested; recommend forensic review of affected hosts.")
            calls += [("recommend_action", {"action": "isolate_host", "target": h,
                                            "reason": "Host communicating with known C2 infrastructure"})
                      for h in self.hosts]
            calls += [("recommend_action", {"action": "block_ip", "target": ip,
                                            "reason": f"Threat intel risk score {scores[ip]}"})
                      for ip in self.ips if scores.get(ip, 0) >= 70]
            main = (self.hosts or self.ips or ["unknown"])[0]
            calls.append(("recommend_action", {"action": "create_ticket", "target": main,
                                               "title": f"Confirmed malicious activity on {main}",
                                               "reason": "Track incident response"}))
        elif event_types & self.BENIGN_EVENTS and max_risk < 40:
            verdict, conf, techniques = "false_positive", 0.85, []
            summary = ("Activity explained by a documented benign event "
                       f"({', '.join(sorted(event_types & self.BENIGN_EVENTS))}) and no risky indicators.")
        else:
            verdict, conf, techniques = "needs_human", 0.5, self._mitre()
            summary = f"Evidence is mixed (max indicator risk {max_risk}). A human analyst should review."

        calls.append(("submit_verdict", {"verdict": verdict, "confidence": conf,
                                         "mitre_techniques": techniques, "summary": summary}))
        return self._respond("Evidence reviewed; submitting decision.", calls)
