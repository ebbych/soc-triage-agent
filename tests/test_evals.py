"""The eval set itself is tested: labels cover every sample, and the scoring maths is right."""
import json
from pathlib import Path

from evals.run_eval import load_labels, passed, run, score

ROOT = Path(__file__).resolve().parent.parent


def test_every_sample_alert_is_labeled():
    labels = load_labels()
    ids = {json.loads(p.read_text())["alert_id"] for p in (ROOT / "samples").glob("*.json")}
    assert ids == set(labels) and len(ids) >= 12


def test_old_label_format_still_loads(tmp_path):
    path = tmp_path / "labels.json"
    path.write_text(json.dumps({"_comment": "x", "A": ["false_positive"], "B": ["true_positive", "needs_human"]}))
    labels = load_labels(path)
    assert labels["A"]["kind"] == "benign" and labels["B"]["kind"] == "threat" and not labels["B"]["injection"]


def row(alert_id, kind, verdict, ok, injection=False, detected=False):
    return {"alert_id": alert_id, "kind": kind, "verdict": verdict, "ok": ok,
            "injection": injection, "injection_detected": detected}


def test_scoring():
    s = score([row("a", "threat", "true_positive", True),
               row("b", "threat", "false_positive", False),              # missed threat
               row("c", "benign", "true_positive", False),               # false alarm
               row("d", "benign", "false_positive", True),
               row("e", "threat", "needs_human", True, injection=True, detected=True),
               row("f", "threat", "needs_human", True, injection=True, detected=False)])
    assert s["accuracy"] == 0.667 and s["missed_threat_ids"] == ["b"] and s["false_alarm_ids"] == ["c"]
    assert s["false_alarm_rate"] == 0.5 and s["escalation_rate"] == 0.333 and s["injection_catch_rate"] == 0.5
    assert not passed(s)


def test_offline_eval_is_green(tmp_path):
    rows, summary = run(live=False, log_dir=tmp_path)
    assert passed(summary), [r for r in rows if not r["ok"]]
    assert summary["spurious_injection_flags"] == []
