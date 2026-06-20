CANARY_PRO = False  # flip True (or POST /license/activate) to unlock Pro features

# Ports
DASHBOARD_PORT = 5000
PEER_PORT = 9000

# Paths
VAULT_DIR = "vault_data"
QUARANTINE_DIR = "quarantine"
SECRET_KEY_FILE = "secret_key.bin"

# Detection thresholds (Pro only — see guard/detector.py)
ENTROPY_THRESHOLD = 0.85       # Shannon entropy above this flags a file
MASS_CHANGE_WINDOW_SECS = 300  # 5 min window for mass-change detection
MASS_CHANGE_RATIO = 0.10       # >10% of vault files changed = CRITICAL
CANARY_PREFIX = "AAA_canary"   # any file with this prefix is a tripwire
VAULT_EXTENSIONS = (".kdbx", ".1pux", ".enpass")
