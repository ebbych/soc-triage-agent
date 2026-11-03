"""Tools the agent can call.

Read-only investigation tools are answered from the JSON files in data/ so the project runs
anywhere. To go live, replace each _method body with a real API call (VirusTotal, AbuseIPDB,
your CMDB, Splunk/Chronicle search, Azure AD, etc.) and keep the return shape the same.

recommend_action and submit_verdict are control tools: the agent loop routes them through the
guardrails instead of executing them here.
"""
import json
from pathlib import Path

from .config import DATA_DIR


class ToolError(Exception):
    pass


def _schema(name, description, properties, required):
    return {"name": name, "description": description,
            "input_schema": {"type": "object", "properties": properties, "required": required}}


READ_ONLY_TOOLS = [
    _schema("lookup_ip_reputation",
            "Look up threat-intel reputation for an IP address. Returns risk_score 0-100 (null if unknown), "
            "category and analyst notes.",
            {"ip": {"type": "string"}}, ["ip"]),
    _schema("lookup_domain_reputation",
            "Look up threat-intel reputation for a domain. Returns risk_score 0-100 (null if unknown), "
            "category, registration date and notes.",
            {"domain": {"type": "string"}}, ["domain"]),
    _schema("get_asset_info",
            "Get inventory details for a host: environment, OS, role, owner and criticality "
            "(low, medium, high, critical).",
            {"hostname": {"type": "string"}}, ["hostname"]),
    _schema("get_user_info",
            "Get directory details for a user account: department, title, MFA status and criticality.",
            {"username": {"type": "string"}}, ["username"]),
    _schema("search_related_events",
            "Search the log store for events involving an entity (hostname, username, IP or domain) "
            "in the last N hours (1-72).",
            {"entity": {"type": "string"}, "hours": {"type": "integer", "default": 24}}, ["entity"]),
]

CONTROL_TOOLS = [
    _schema("recommend_action",
            "Request a response action. create_ticket runs automatically. block_ip, isolate_host and "
            "disable_user need human approval and may be denied or blocked by policy. Only one ticket is "
            "allowed per alert.",
            {"action": {"type": "string", "enum": ["create_ticket", "block_ip", "isolate_host", "disable_user"]},
             "target": {"type": "string",
                        "description": "An entity from the alert: the IP, host or user to act on. For "
                                       "create_ticket, the main affected entity."},
             "title": {"type": "string",
                       "description": "Required for create_ticket: a specific ticket title naming the threat "
                                      "and asset, e.g. 'SQLi bypassing WAF on api-gw-01'."},
             "reason": {"type": "string", "description": "Evidence-based justification"}},
            ["action", "target", "reason"]),
    _schema("submit_verdict",
            "Submit your final triage decision. Call exactly once, at the end.",
            {"verdict": {"type": "string", "enum": ["true_positive", "false_positive", "needs_human"]},
             "confidence": {"type": "number", "minimum": 0, "maximum": 1},
             "mitre_techniques": {"type": "array", "items": {"type": "string"},
                                  "description": "MITRE ATT&CK technique IDs, e.g. T1071.004"},
             "summary": {"type": "string",
                         "description": "What happened, key evidence, actions taken, recommended next steps"}},
            ["verdict", "confidence", "mitre_techniques", "summary"]),
]

TOOL_SCHEMAS = READ_ONLY_TOOLS + CONTROL_TOOLS
READ_ONLY_NAMES = {t["name"] for t in READ_ONLY_TOOLS}


class ToolExecutor:
    def __init__(self, data_dir: Path = DATA_DIR):
        data_dir = Path(data_dir)
        self.intel = json.loads((data_dir / "threat_intel.json").read_text(encoding="utf-8"))
        self.assets = json.loads((data_dir / "assets.json").read_text(encoding="utf-8"))
        self.users = json.loads((data_dir / "users.json").read_text(encoding="utf-8"))
        self.events = json.loads((data_dir / "events.json").read_text(encoding="utf-8"))

    def run(self, name: str, args: dict) -> dict:
        if name not in READ_ONLY_NAMES:
            raise ToolError(f"Unknown tool: {name}")
        return getattr(self, f"_{name}")(**args)

    def _lookup_ip_reputation(self, ip: str) -> dict:
        ip = ip.strip()
        record = self.intel["ips"].get(ip)
        return {"ip": ip, **(record or {"risk_score": None, "category": "unknown", "notes": "No intel on this IP."})}

    def _lookup_domain_reputation(self, domain: str) -> dict:
        domain = domain.strip().lower()
        record = self.intel["domains"].get(domain)
        return {"domain": domain,
                **(record or {"risk_score": None, "category": "unknown", "notes": "No intel on this domain."})}

    def _get_asset_info(self, hostname: str) -> dict:
        record = self.assets.get(hostname.strip())
        if not record:
            return {"hostname": hostname, "found": False}
        return {"hostname": hostname, "found": True, **record}

    def _get_user_info(self, username: str) -> dict:
        record = self.users.get(username.strip())
        if not record:
            return {"username": username, "found": False}
        return {"username": username, "found": True, **record}

    def _search_related_events(self, entity: str, hours: int = 24) -> dict:
        hours = max(1, min(int(hours), 72))
        entity = entity.strip()
        # Sample data has no clock, so the window is not applied. A real backend would filter by time.
        matches = [e for e in self.events if entity in e.get("entities", [])]
        return {"entity": entity, "hours": hours, "count": len(matches), "events": matches[:50]}
