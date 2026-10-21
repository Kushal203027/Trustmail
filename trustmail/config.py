"""
TrustMail: Configuration Module.
Provides centralized, safe configuration defaults for the local prototype.
"""

from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
DATABASE_PATH = DATA_DIR / "trustmail.db"

# Ingress Limits
# Enforce strict 1 MB size limit as specified in foundation requirements
MAX_INPUT_BYTES = 1 * 1024 * 1024  # 1,048,576 bytes

# Networking & Binding
HOST = "127.0.0.1"  # Local development only, do not expose to public interfaces
PORT = 8000

# Application & Model Metadata
APP_VERSION = "0.1.0"
ASSESSMENT_VERSION = "1.0.0-deterministic"
SYSTEM_NAME = "TrustMail Prototype"

# Ensure data directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
