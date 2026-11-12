"""Threat intelligence.

Every lookup starts with the local file in data/threat_intel.json, so the project runs offline.
When live intel is switched on and an API key is present, results from these providers are merged in:

    VirusTotal   VT_API_KEY          IPs, domains, file hashes
    AbuseIPDB    ABUSEIPDB_API_KEY   IPs
    CISA KEV     (no key)            is this CVE known to be exploited in the wild?

Safety rules built in:
- Inputs are validated before they are placed in a URL.
- Private and reserved IP addresses are never sent to an outside service.
- A provider that fails or times out is recorded in provider_errors and never breaks a run.

Refresh the full CISA KEV catalog (otherwise a small bundled sample is used):

    python -m agent.intel --refresh-kev
"""
import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .config import DATA_DIR, INTEL_TIMEOUT, KEV_CACHE, KEV_URL

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
HASH_RE = re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class IntelError(Exception):
    pass


def http_json(url: str, headers: dict, timeout: float = INTEL_TIMEOUT):
    """GET a URL and parse JSON. Returns None on 404 (the provider has no record)."""
    request = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise IntelError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise IntelError(type(exc).__name__) from exc


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Providers. Each returns a small dict with a 0-100 risk_score, or None if it has no record.
# ---------------------------------------------------------------------------
class VirusTotal:
    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, fetch=http_json):
        self.headers = {"x-apikey": api_key}
        self.fetch = fetch

    def _lookup(self, kind: str, value: str):
        body = self.fetch(f"{self.BASE}/{kind}/{urllib.parse.quote(value, safe='')}", self.headers)
        if not body:
            return None
        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        out = {"source": self.name,
               # Simple, explainable scoring: 10 points per engine calling it malicious, 5 per suspicious.
               "risk_score": min(100, malicious * 10 + suspicious * 5),
               "engines_malicious": malicious, "engines_suspicious": suspicious,
               "engines_total": sum(int(v) for v in stats.values() if isinstance(v, int))}
        if attrs.get("meaningful_name"):
            out["file_name"] = str(attrs["meaningful_name"])[:120]
        if attrs.get("popular_threat_classification", {}).get("suggested_threat_label"):
            out["threat_label"] = str(attrs["popular_threat_classification"]["suggested_threat_label"])[:120]
        return out

    def ip(self, ip: str):
        return self._lookup("ip_addresses", ip)

    def domain(self, domain: str):
        return self._lookup("domains", domain)

    def file(self, file_hash: str):
        return self._lookup("files", file_hash)


class AbuseIPDB:
    name = "abuseipdb"
    URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, fetch=http_json):
        self.headers = {"Key": api_key}
        self.fetch = fetch

    def ip(self, ip: str):
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        body = self.fetch(f"{self.URL}?{query}", self.headers)
        data = (body or {}).get("data")
        if not data:
            return None
        return {"source": self.name, "risk_score": int(data.get("abuseConfidenceScore", 0)),
                "total_reports": data.get("totalReports"), "country": data.get("countryCode"),
                "usage_type": data.get("usageType"), "isp": data.get("isp")}


class KevCatalog:
    """CISA Known Exploited Vulnerabilities. Uses the downloaded catalog if present, otherwise the
    small bundled sample. With only the sample loaded, a miss means 'unknown', not 'not exploited'."""

    def __init__(self, cache: Path = KEV_CACHE, sample: Path | None = None):
        sample = sample or DATA_DIR / "kev_sample.json"
        self.full = Path(cache).exists()
        path = Path(cache) if self.full else sample
        body = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        self.version = body.get("catalogVersion") or body.get("dateReleased") or "unknown"
        self.entries = {v["cveID"].upper(): v for v in body.get("vulnerabilities", []) if v.get("cveID")}

    def lookup(self, cve: str) -> dict:
        entry = self.entries.get(cve)
        catalog = "full" if self.full else "bundled_sample"
        if not entry:
            if self.full:
                return {"cve": cve, "in_kev": False, "catalog": catalog, "catalog_version": self.version}
            return {"cve": cve, "in_kev": None, "catalog": catalog,
                    "note": "Not in the bundled sample. Only the full catalog can rule a CVE out; "
                            "run: python -m agent.intel --refresh-kev"}
        keep = ("vendorProject", "product", "vulnerabilityName", "dateAdded", "requiredAction", "dueDate",
                "knownRansomwareCampaignUse")
        return {"cve": cve, "in_kev": True, "catalog": catalog, "catalog_version": self.version,
                **{k: entry[k] for k in keep if entry.get(k)}}

    @staticmethod
    def refresh(cache: Path = KEV_CACHE, url: str = KEV_URL, fetch=http_json) -> int:
        body = fetch(url, {}, 60)
        if not body or not isinstance(body.get("vulnerabilities"), list):
            raise IntelError("The KEV feed did not return a catalog.")
        Path(cache).parent.mkdir(parents=True, exist_ok=True)
        Path(cache).write_text(json.dumps(body), encoding="utf-8")
        return len(body["vulnerabilities"])


# ---------------------------------------------------------------------------
# The facade the tools call
# ---------------------------------------------------------------------------
class ThreatIntel:
    def __init__(self, data_dir: Path = DATA_DIR, providers: list | None = None, kev: KevCatalog | None = None):
        self.local = json.loads((Path(data_dir) / "threat_intel.json").read_text(encoding="utf-8"))
        self.providers = providers or []
        self.kev = kev or KevCatalog()

    @classmethod
    def from_env(cls, data_dir: Path = DATA_DIR, live: bool = True) -> "ThreatIntel":
        providers = []
        if live:
            if os.getenv("VT_API_KEY"):
                providers.append(VirusTotal(os.environ["VT_API_KEY"]))
            if os.getenv("ABUSEIPDB_API_KEY"):
                providers.append(AbuseIPDB(os.environ["ABUSEIPDB_API_KEY"]))
        return cls(data_dir, providers)

    @property
    def provider_names(self) -> list[str]:
        return ["local_file"] + [p.name for p in self.providers]

    def _merge(self, key: str, value: str, section: str, method: str, unknown_note: str, send: bool = True):
        record = dict(self.local.get(section, {}).get(value) or {})
        result = {key: value,
                  **(record or {"risk_score": None, "category": "unknown", "notes": unknown_note})}
        checked, details, errors = ["local_file"], [], []
        scores = [record["risk_score"]] if record.get("risk_score") is not None else []
        for provider in self.providers:
            lookup = getattr(provider, method, None)
            if not lookup or not send:
                continue
            checked.append(provider.name)
            try:
                found = lookup(value)
            except IntelError as exc:
                errors.append(f"{provider.name}: {exc}")
                continue
            if found:
                details.append(found)
                scores.append(found["risk_score"])
        # The highest score wins: one credible source calling it bad is enough to look closer.
        result["risk_score"] = max(scores) if scores else None
        result["sources_checked"] = checked
        if details:
            result["providers"] = details
        if errors:
            result["provider_errors"] = errors
        return result

    def ip(self, ip: str) -> dict:
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"'{ip[:60]}' is not a valid IP address") from None
        public = is_public_ip(ip)
        result = self._merge("ip", ip, "ips", "ip", "No intel on this IP.", send=public)
        if not public and self.providers:
            result["external_lookup"] = "skipped: private or reserved address"
        return result

    def domain(self, domain: str) -> dict:
        domain = domain.strip().lower().rstrip(".")
        if not DOMAIN_RE.match(domain):
            raise ValueError(f"'{domain[:60]}' is not a valid domain name")
        return self._merge("domain", domain, "domains", "domain", "No intel on this domain.")

    def file_hash(self, file_hash: str) -> dict:
        file_hash = file_hash.strip().lower()
        if not HASH_RE.match(file_hash):
            raise ValueError("hash must be an MD5, SHA-1 or SHA-256 hex string")
        return self._merge("hash", file_hash, "hashes", "file", "No intel on this file hash.")

    def cve(self, cve: str) -> dict:
        cve = cve.strip().upper()
        if not CVE_RE.match(cve):
            raise ValueError("cve must look like CVE-2024-12345")
        return self.kev.lookup(cve)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Threat intel utilities")
    parser.add_argument("--refresh-kev", action="store_true", help="Download the full CISA KEV catalog")
    args = parser.parse_args(argv)
    if args.refresh_kev:
        try:
            count = KevCatalog.refresh()
        except IntelError as exc:
            print(f"Could not download the KEV catalog: {exc}", file=sys.stderr)
            return 1
        print(f"Saved {count} known exploited vulnerabilities to {KEV_CACHE}")
        return 0
    intel = ThreatIntel.from_env()
    print(f"Providers: {', '.join(intel.provider_names)}")
    print(f"KEV catalog: {'full' if intel.kev.full else 'bundled sample'} ({len(intel.kev.entries)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
