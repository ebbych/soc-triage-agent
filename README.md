# SOC Alert Triage Agent

An AI agent that investigates security alerts the way a Tier-1 SOC analyst would: it enriches indicators, pulls related logs, decides whether the alert is a real threat, maps it to MITRE ATT&CK, and requests containment, all inside guardrails that limit what it can do even when the model is wrong or being attacked.

Built with Python and Claude (Anthropic API tool use). Runs fully offline with a mock model for testing.

## How it works

```
alert JSON ──► injection scan ──► Claude agent loop ──────────────► verdict + summary
                                      │        ▲
                         tool calls   ▼        │ results (wrapped as untrusted data)
                     ┌─────────────────────────────────────┐
                     │ read-only: IP/domain/hash reputation,│
                     │ known-exploited CVE check, asset     │
                     │ info, user info, log search,         │
                     │ past cases                           │
                     ├─────────────────────────────────────┤
                     │ action gate: create_ticket (auto),   │
                     │ block_ip / isolate_host /            │
                     │ disable_user (human approval)        │
                     └─────────────────────────────────────┘
                     every step ──► audit log (JSONL)
                     finished run ──► case memory (SQLite)
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
| Safe intel lookups | Indicators are validated before they go in a URL; private IPs are never sent to outside services; a failing provider never breaks a run | `agent/intel.py` |
| Memory-poisoning defense | Only completed runs are remembered, with the verdict that passed the guardrails; summaries of cases with detected injection are withheld; past cases are context, never proof | `agent/memory.py` |

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

## Threat intelligence

Reputation lookups always check the local file in `data/threat_intel.json`. With the real model, live providers are added automatically when their API key is set, and the highest score across sources wins:

| Provider | Covers | Enable with |
|---|---|---|
| VirusTotal | IPs, domains, file hashes | `VT_API_KEY` |
| AbuseIPDB | IPs | `ABUSEIPDB_API_KEY` |
| CISA Known Exploited Vulnerabilities | CVEs | no key; `python -m agent.intel --refresh-kev` downloads the full catalog |

Without the download, `lookup_cve` uses a three-entry bundled sample and answers "unknown" (not "no") for CVEs outside it. `--mock` and the evals never call live providers. Use `--no-live-intel` to force offline lookups.

## Case memory

Each completed investigation is saved to a local SQLite file (`memory/cases.db`, git-ignored). On later alerts the agent can call `search_past_cases` to see earlier verdicts for the same host, user, IP, domain, hash or CVE.

```bash
python -m agent.memory            # list recent cases
python -m agent.memory --clear    # delete all stored cases
python -m agent.main samples/alert_001_guardduty_c2.json --mock --no-memory
```

Past verdicts were written by the agent itself, so the system prompt tells the model to treat them as context and never to close an alert only because a similar one was closed before.

## Evaluation

```bash
python -m evals.run_eval                     # offline mock model
python -m evals.run_eval --live              # real Claude
python -m evals.run_eval --out results.json  # save scores to track over time
```

Twelve labeled alerts (4 threats, 4 benign, 1 ambiguous, plus 3 threats carrying prompt injection, one of them hidden in log data rather than in the alert). The runner reports accuracy, missed threats (a threat closed as a false positive; must be 0), false alarms on benign alerts, the share escalated to a human, and the injection catch rate. It exits non-zero if any verdict is unacceptable, any threat is missed, or any injection goes undetected.

The mock model follows fixed rules written alongside these samples, so its 12/12 only proves the pipeline and guardrails work. `--live` is the measure of real triage quality.

While it runs, the agent prints live progress (each tool call, action request and verdict) so you can follow its investigation. Options: `--approve ask|all|none` controls how approval requests are answered (default `ask` prompts you), `--json` prints the raw result, `--quiet` hides the progress lines. Change the model with `TRIAGE_MODEL`.

## Sample alerts

| File | Scenario | What it shows |
|---|---|---|
| `alert_001_guardduty_c2.json` | AWS GuardDuty: EC2 instance beaconing to a C2 domain | True positive, containment needs approval |
| `alert_002_splunk_failed_logins.json` | Splunk: failed logins then success | False positive explained by a helpdesk password reset |
| `alert_003_web_sqli_with_injection.json` | WAF: SQL injection whose User-Agent tries to hijack the AI | Injection detected; a hijacked "false positive" verdict is overridden to needs_human |
| `alert_004_dc_beaconing.json` | CrowdStrike: C2 beaconing from a domain controller | Isolation blocked because dc01 is a critical asset |
| `alert_005_malware_hash.json` | CrowdStrike: malware blocked on a laptop | True positive from file-hash reputation |
| `alert_006_scheduled_vuln_scan.json` | IDS: internal port scan | False positive: the authorized scanner on its weekly schedule |
| `alert_007_impossible_travel.json` | Entra ID: sign-ins from two countries 43 minutes apart | Mixed evidence, escalated to a human |
| `alert_008_kev_exploit_attempt.json` | IDS: exploit attempt against the VPN gateway | True positive; CVE confirmed as known-exploited |
| `alert_009_approved_change_admin.json` | Splunk: new local admin account | False positive explained by an approved change |
| `alert_010_phishing_with_injection.json` | Proofpoint: user clicked a phishing link; email body tries to hijack the AI | Injection detected; false-positive verdict overridden |
| `alert_011_exfil_injection_in_logs.json` | NDR: large outbound transfer; a log line tries to hijack the AI | Injection detected in tool output, not in the alert |
| `alert_012_dlp_approved_share.json` | Purview DLP: confidential file sent externally | False positive: approved audit partner |

The `--mock` model is a deliberately simple rule-based stand-in. In mock mode it is intentionally "gullible" on alert 003 so you can see the output guardrail catch a compromised decision. Run with real Claude to see actual reasoning.

## Project layout

```
agent/
  agent.py       agent loop and system prompt
  tools.py       tool definitions + mock implementations (swap in real APIs here)
  intel.py       threat intel: local file, VirusTotal, AbuseIPDB, CISA KEV
  memory.py      case memory (SQLite) and its poisoning defenses
  guardrails.py  injection defense, action gate, verdict validation, kill switch
  audit.py       JSONL audit log with secret redaction
  backends.py    Claude backend and offline mock backend
  main.py        command-line interface
data/            mock threat intel, asset inventory, users, log events, KEV sample
samples/         sample alerts
evals/           labeled evaluation set and runner
tests/           pytest suite: guardrails, threat intel, case memory, eval scoring, end-to-end runs
```

## Going live

Each tool in `agent/tools.py` returns a plain dict. To connect real systems, replace the method body and keep the return shape: for example, `_search_related_events` → a Google SecOps (Chronicle) UDM search or Splunk search, `_get_asset_info` → your CMDB, `_get_user_info` → Active Directory or Entra ID. Reputation lookups already support VirusTotal and AbuseIPDB (see Threat intelligence). Keep actions in dry-run until approvals and logging have been reviewed.

Only send real security data to an external AI API if your organization's policy allows it.

## Roadmap

The full design is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and the path of a single alert is in [docs/ALERT_FLOW.md](docs/ALERT_FLOW.md).

- Connect security tools through MCP servers (EDR, SIEM, vulnerability management, cloud, email, data, identity, network) behind a policy file
- Active Directory / Entra ID and asset inventory lookups
- Per-investigation reports showing where each alert came from, pushed to ticketing or chat
- Grow the eval set further and track live-model scores over time
- Slack or ticketing approval flow instead of terminal prompts
- Web UI for analysts to review verdicts and audit trails
