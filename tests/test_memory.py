"""Case-memory tests, including the poisoning defenses."""
import json
from pathlib import Path

import pytest

from agent.agent import triage
from agent.backends import MockBackend
from agent.guardrails import deny_all
from agent.memory import CaseMemory
from agent.tools import ToolExecutor

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(name):
    return json.loads((SAMPLES / name).read_text())


@pytest.fixture
def memory():
    return CaseMemory(":memory:")


def run(name, memory, tmp_path):
    alert = load(name)
    return alert, triage(alert, MockBackend(alert), deny_all, log_dir=tmp_path, memory=memory)


def test_completed_run_is_saved_and_found_by_any_entity(memory, tmp_path):
    run("alert_001_guardduty_c2.json", memory, tmp_path)
    assert memory.count() == 1
    for entity in ("web-prod-03", "185.220.101.47", "UPDATE-CDN-SYNC.XYZ"):   # search is case-insensitive
        cases = memory.search(entity)
        assert len(cases) == 1 and cases[0]["verdict"] == "true_positive"
    assert memory.search("some-other-host") == []


def test_unfinished_run_is_not_remembered(memory, tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGE_KILL_SWITCH", "1")
    _, r = run("alert_001_guardduty_c2.json", memory, tmp_path)
    assert r["status"] == "killed" and memory.count() == 0


def test_agent_sees_past_case_on_the_next_run(memory, tmp_path):
    run("alert_001_guardduty_c2.json", memory, tmp_path)
    _, r = run("alert_001_guardduty_c2.json", memory, tmp_path)
    out = ToolExecutor(memory=memory, alert_id="GD-7f3a91").run("search_past_cases", {"entity": "web-prod-03"})
    assert out["count"] == 2 and out["cases"][0]["same_alert_as_current"] is True
    events = [json.loads(line) for line in Path(r["audit_log"]).read_text().splitlines()]
    assert any(e["event"] == "tool_call" and e["name"] == "search_past_cases" for e in events)
    assert any(e["event"] == "memory.case_saved" for e in events)


def test_stored_verdict_is_the_one_that_passed_the_guardrails(memory, tmp_path):
    # The gullible mock says false_positive; the guardrail overrides it. Memory must hold the override.
    run("alert_003_web_sqli_with_injection.json", memory, tmp_path)
    case = memory.search("api-gw-01")[0]
    assert case["verdict"] == "needs_human" and case["verdict_set_by_guardrail"] is True


def test_summary_of_an_injected_case_is_withheld(memory, tmp_path):
    run("alert_003_web_sqli_with_injection.json", memory, tmp_path)
    case = memory.search("203.0.113.77")[0]
    assert case["injection_detected"] is True and "withheld" in case["summary"]
    assert "penetration test" not in json.dumps(case)


def test_past_case_cannot_carry_injection_into_a_clean_alert(memory, tmp_path):
    run("alert_003_web_sqli_with_injection.json", memory, tmp_path)
    alert = load("alert_003_web_sqli_with_injection.json")
    alert["alert_id"], alert["raw"] = "NEW-1", {"status": 500}          # same entities, clean text
    r = triage(alert, MockBackend(alert), deny_all, log_dir=tmp_path, memory=memory)
    assert r["injection_findings"] == []


def test_memory_off_by_default_and_tool_says_so(tmp_path):
    out = ToolExecutor().run("search_past_cases", {"entity": "web-prod-03"})
    assert out["count"] == 0 and "switched off" in out["note"]


def test_memory_failure_never_fails_a_triage(tmp_path):
    class Broken(CaseMemory):
        def save(self, alert, result):
            raise RuntimeError("disk full")
    alert = load("alert_001_guardduty_c2.json")
    r = triage(alert, MockBackend(alert), deny_all, log_dir=tmp_path, memory=Broken(":memory:"))
    assert r["status"] == "completed" and r["verdict"] == "true_positive"


def test_clear(memory, tmp_path):
    run("alert_001_guardduty_c2.json", memory, tmp_path)
    memory.clear()
    assert memory.count() == 0 and memory.search("web-prod-03") == []
