"""Reset the simulated state to its clean demo state.

Clears the approvals and audit log in state/ (or BRA_STATE_DIR) and the legacy quarantine log
used by the legacy demo. Later steps add environment state here too.
"""

import shutil
from pathlib import Path

from approvals import DEFAULT_STATE_DIR

LEGACY_LOG = Path(__file__).parent / "legacy" / "data" / "actions_log.csv"
HEADER = "hostname,quarantined_at,reason\n"


def main() -> None:
    if DEFAULT_STATE_DIR.exists():
        shutil.rmtree(DEFAULT_STATE_DIR)
    print(f"Cleared approvals and audit log: {DEFAULT_STATE_DIR}")
    LEGACY_LOG.write_text(HEADER, encoding="utf-8")
    print(f"Reset legacy action log: {LEGACY_LOG}")


if __name__ == "__main__":
    main()
