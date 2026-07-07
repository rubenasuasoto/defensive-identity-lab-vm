from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LABS_CONFIG = ROOT / "labs.json"
SITE_DIR = ROOT / "site"
SITE_INDEX = SITE_DIR / "index.html"
LIVE_DB = ROOT / "live_lab.sqlite"
