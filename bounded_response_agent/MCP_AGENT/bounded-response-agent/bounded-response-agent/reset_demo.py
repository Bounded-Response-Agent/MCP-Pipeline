"""Reset the simulated state to its clean demo state.

Right now the only mutable state is the legacy quarantine log used by the legacy demo
(legacy/data/actions_log.csv). Later steps add state for the new scenario here too.
"""

from pathlib import Path


LEGACY_LOG = Path(__file__).parent / "legacy" / "data" / "actions_log.csv"
HEADER = "hostname,quarantined_at,reason\n"


def main() -> None:
    LEGACY_LOG.write_text(HEADER, encoding="utf-8")
    print(f"Reset legacy action log: {LEGACY_LOG}")


if __name__ == "__main__":
    main()
