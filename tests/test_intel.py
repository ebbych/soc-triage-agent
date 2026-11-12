"""Threat-intel tests. No network: providers are given a fake fetch function."""
import json
from pathlib import Path

import pytest

from agent.intel import AbuseIPDB, IntelError, KevCatalog, ThreatIntel, VirusTotal, is_public_ip
from agent.tools import ToolExecutor

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_IP = "8.8.8.8"


def vt_body(malicious=0, suspicious=0, harmless=60):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": 10}}}}


def fake_fetch(body, calls=None):
    def fetch(url, headers, timeout=10):
        if calls is not None:
            calls.append((url, headers))
        if isinstance(body, Exception):
            raise body
        return body
    return fetch


def test_offline_lookup_keeps_original_shape():
    out = ThreatIntel().ip("185.220.101.47")
    assert out["risk_score"] == 92 and out["category"] == "c2_infrastructure"
    assert out["sources_checked"] == ["local_file"]


def test_unknown_indicator_has_null_score():
    assert ThreatIntel().domain("example.org")["risk_score"] is None


def test_virustotal_score_and_request():
    calls = []
    vt = VirusTotal("vt-key", fake_fetch(vt_body(malicious=8, suspicious=2), calls))
    out = vt.ip(PUBLIC_IP)
    assert out["risk_score"] == 90 and out["engines_malicious"] == 8
    url, headers = calls[0]
    assert url == f"https://www.virustotal.com/api/v3/ip_addresses/{PUBLIC_IP}" and headers == {"x-apikey": "vt-key"}


def test_virustotal_score_is_capped_and_missing_record_is_none():
    assert VirusTotal("k", fake_fetch(vt_body(malicious=40))).domain("bad.example")["risk_score"] == 100
    assert VirusTotal("k", fake_fetch(None)).file("a" * 64) is None


def test_abuseipdb_parsing():
    body = {"data": {"abuseConfidenceScore": 77, "totalReports": 31, "countryCode": "NL", "isp": "Example ISP"}}
    calls = []
    out = AbuseIPDB("ab-key", fake_fetch(body, calls)).ip(PUBLIC_IP)
    assert out["risk_score"] == 77 and out["total_reports"] == 31
    assert "ipAddress=8.8.8.8" in calls[0][0] and calls[0][1] == {"Key": "ab-key"}


def test_highest_score_wins_across_sources():
    intel = ThreatIntel(providers=[VirusTotal("k", fake_fetch(vt_body(malicious=1))),
                                   AbuseIPDB("k", fake_fetch({"data": {"abuseConfidenceScore": 64}}))])
    out = intel.ip(PUBLIC_IP)
    assert out["risk_score"] == 64
    assert out["sources_checked"] == ["local_file", "virustotal", "abuseipdb"] and len(out["providers"]) == 2


def test_private_ip_is_never_sent_to_a_provider():
    calls = []
    intel = ThreatIntel(providers=[VirusTotal("k", fake_fetch(vt_body(malicious=9), calls))])
    out = intel.ip("10.20.5.14")
    assert calls == [] and out["risk_score"] == 0 and "skipped" in out["external_lookup"]
    assert not is_public_ip("192.168.1.10") and not is_public_ip("203.0.113.77") and is_public_ip(PUBLIC_IP)


def test_provider_failure_does_not_break_lookup():
    intel = ThreatIntel(providers=[VirusTotal("k", fake_fetch(IntelError("HTTP 429")))])
    out = intel.ip(PUBLIC_IP)
    assert out["risk_score"] is None and out["provider_errors"] == ["virustotal: HTTP 429"]


@pytest.mark.parametrize("method,bad", [
    ("ip", "1.2.3.4/../../x"), ("domain", "evil.com/path?x=1"), ("file_hash", "nothex"), ("cve", "CVE-24-1"),
])
def test_invalid_input_rejected_before_any_request(method, bad):
    calls = []
    intel = ThreatIntel(providers=[VirusTotal("k", fake_fetch(vt_body(), calls))])
    with pytest.raises(ValueError):
        getattr(intel, method)(bad)
    assert calls == []


def test_kev_sample_hit_and_honest_miss(tmp_path):
    kev = KevCatalog(cache=tmp_path / "none.json")
    hit = kev.lookup("CVE-2021-44228")
    assert hit["in_kev"] is True and hit["catalog"] == "bundled_sample" and hit["product"] == "Log4j2"
    assert kev.lookup("CVE-2099-0001")["in_kev"] is None      # sample cannot rule a CVE out


def test_kev_full_catalog_can_say_no(tmp_path):
    cache = tmp_path / "kev.json"
    feed = {"catalogVersion": "2026.11.10", "vulnerabilities": [{"cveID": "CVE-2025-0001", "product": "Thing"}]}
    assert KevCatalog.refresh(cache, fetch=lambda url, headers, timeout: feed) == 1
    kev = KevCatalog(cache=cache)
    assert kev.lookup("CVE-2025-0001")["in_kev"] is True
    assert kev.lookup("CVE-2021-44228")["in_kev"] is False


def test_new_tools_are_wired_into_the_executor():
    ex = ToolExecutor()
    sample = json.loads((ROOT / "samples" / "alert_005_malware_hash.json").read_text())
    assert ex.run("lookup_file_hash", {"hash": sample["entities"]["hashes"][0]})["risk_score"] == 96
    assert ex.run("lookup_cve", {"cve": "cve-2024-3400"})["in_kev"] is True
