"""Central settings. Every value can be overridden with an environment variable."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"

# Claude model used by the live backend.
MODEL = os.getenv("TRIAGE_MODEL", "claude-sonnet-5-5")

# Guardrail limits.
MAX_STEPS = int(os.getenv("TRIAGE_MAX_STEPS", "12"))          # model turns per alert
MAX_ACTIONS = int(os.getenv("TRIAGE_MAX_ACTIONS", "3"))       # containment/ticket actions per alert
MIN_CONFIDENCE = float(os.getenv("TRIAGE_MIN_CONFIDENCE", "0.6"))  # below this, escalate to a human

# Threat intelligence. Live providers switch on when their API key is set (VT_API_KEY, ABUSEIPDB_API_KEY).
INTEL_TIMEOUT = float(os.getenv("TRIAGE_INTEL_TIMEOUT", "10"))  # seconds per provider call
KEV_URL = os.getenv("TRIAGE_KEV_URL",
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
KEV_CACHE = Path(os.getenv("TRIAGE_KEV_CACHE", str(DATA_DIR / "kev_catalog.json")))

# Case memory: SQLite file holding past investigations.
CASE_DB = Path(os.getenv("TRIAGE_CASE_DB", str(ROOT / "memory" / "cases.db")))

# Kill switch: set TRIAGE_KILL_SWITCH=1 or create this file to stop all agent runs immediately.
KILL_SWITCH_FILE = ROOT / "KILL_SWITCH"
