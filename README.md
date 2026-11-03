# SOC Alert Triage Agent

An AI agent that investigates security alerts the way a Tier-1 SOC analyst would: it enriches indicators, pulls related logs, decides whether the alert is a real threat, maps it to MITRE ATT&CK, and requests containment, all inside guardrails that limit what it can do even when the model is wrong or being attacked.

Built with Python and Claude (Anthropic API tool use). Runs fully offline with a mock model for testing.

## How it works

```
alert JSON ──► injection scan ──► Claude agent loop ──────────────► verdict + summary
                                      │        ▲
                         tool calls   ▼        │ results (wrapped as untrusted data)
                     ┌─────────────────────────────────────┐
                     │ read-only: IP/domain reputation,     │
                     │ asset info, user info, log search    │
                     ├─────────────────────────────────────┤
                     │ action gate: create_ticket (auto),   │
                     │ block_ip / isolate_host /            │
                     │ disable_user (human approval)        │
                     └─────────────────────────────────────┘
                     every step ──► audit log (JSONL)
```

## Guardrails

| Guardrail | What it does | Where |
|---|---|---|
| Least privilege | Investigation tools are read-only; the agent has no delete or config-change tools at all | `agent/tools.py` |
| Prompt-injection defense | Scans alerts and tool output for injected instructions; wraps all attacker-influenced data in `<untrusted_...>` tags the model is told never to obey; strips forged tags | `agent/guardrails.py` |
| Action allowlist | Only 4 actions exist; anything else is blocked | `ActionGate` |
| Target validation | Actions can only target entities named in the alert | `ActionGate` |
| Critical-asset protection | Domain controllers and other `critical` assets can never be isolated or disabled automatically | `ActionGate` |
| Human approval | High-risk actions pause for an analyst's yes/no | `ActionGate` |
| Output validation | Verdict must match a strict schema; malformed output is rejected and retried | `validate_verdict` |
| Policy overrides | Can't close an alert as a false positive if injection was detected; low confidence escalates to a human | `validate_verdict` |
| Limits + kill switch | Max steps and max actions per alert; `TRIAGE_KILL_SWITCH=1` or a `KILL_SWITCH` file stops all runs | `config.py` |
| Audit logging | Every model turn, tool call, action and guardrail decision is logged as JSONL; API keys are redacted | `agent/audit.py` |
| Dry run | v1 never changes real systems; approved actions are logged as "would do" | `ActionGate` |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Offline, no API key needed
python -m agent.main samples/alert_001_guardduty_c2.json --mock
python -m evals.run_eval
python -m pytest

# With real Claude
export ANTHROPIC_API_KEY=sk-ant-...                    # Windows: set ANTHROPIC_API_KEY=...
python -m agent.main samples/alert_001_guardduty_c2.json
python -m evals.run_eval --live
```

While it runs, the agent prints live progress (each tool call, action request and verdict) so you can follow its investigation. Options: `--approve ask|all|none` controls how approval requests are answered (default `ask` prompts you), `--json` prints the raw result, `--quiet` hides the progress lines. Change the model with `TRIAGE_MODEL`.

## Sample alerts

| File | Scenario | What it shows |
|---|---|---|
| `alert_001_guardduty_c2.json` | AWS GuardDuty: EC2 instance beaconing to a C2 domain | True positive, containment needs approval |
| `alert_002_splunk_failed_logins.json` | Splunk: failed logins then success | False positive explained by a helpdesk password reset |
| `alert_003_web_sqli_with_injection.json` | WAF: SQL injection whose User-Agent tries to hijack the AI | Injection detected; a hijacked "false positive" verdict is overridden to needs_human |
| `alert_004_dc_beaconing.json` | CrowdStrike: C2 beaconing from a domain controller | Isolation blocked because dc01 is a critical asset |

The `--mock` model is a deliberately simple rule-based stand-in. In mock mode it is intentionally "gullible" on alert 003 so you can see the output guardrail catch a compromised decision. Run with real Claude to see actual reasoning.

## Project layout

```
agent/
  agent.py       agent loop and system prompt
  tools.py       tool definitions + mock implementations (swap in real APIs here)
  guardrails.py  injection defense, action gate, verdict validation, kill switch
  audit.py       JSONL audit log with secret redaction
  backends.py    Claude backend and offline mock backend
  main.py        command-line interface
data/            mock threat intel, asset inventory, users, log events
samples/         sample alerts
evals/           labeled evaluation set and runner
tests/           pytest suite for guardrails and end-to-end runs
```

## Going live

Each tool in `agent/tools.py` returns a plain dict. To connect real systems, replace the method body and keep the return shape: for example, `_search_related_events` → a Google SecOps (Chronicle) UDM search or Splunk search, `_lookup_ip_reputation` → VirusTotal or AbuseIPDB, `_get_asset_info` → your CMDB. Keep actions in dry-run until approvals and logging have been reviewed.

Only send real security data to an external AI API if your organization's policy allows it.

## Roadmap

- Real integrations (Google SecOps / Chronicle, VirusTotal, AbuseIPDB)
- Larger labeled eval set and false-positive-rate tracking
- Slack or ticketing approval flow instead of terminal prompts
- Web UI for analysts to review verdicts and audit trails
