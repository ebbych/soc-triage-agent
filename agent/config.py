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

# Kill switch: set TRIAGE_KILL_SWITCH=1 or create this file to stop all agent runs immediately.
KILL_SWITCH_FILE = ROOT / "KILL_SWITCH"
