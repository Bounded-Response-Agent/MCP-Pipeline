"""Reset the simulated action log to its clean demo state."""

from pathlib import Path


ACTIONS_LOG = Path(__file__).parent / "data" / "actions_log.csv"
HEADER = "hostname,quarantined_at,reason\n"


def main() -> None:
    ACTIONS_LOG.write_text(HEADER, encoding="utf-8")
    print(f"Reset demo action log: {ACTIONS_LOG}")


if __name__ == "__main__":
    main()
