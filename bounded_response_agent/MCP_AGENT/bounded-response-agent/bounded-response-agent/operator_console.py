"""Human operator console: the only way to approve or deny a request.

The agent has no tool for this, so it cannot approve its own work. Run it in a second
terminal while the agent waits, or use the inline prompt in client.py.

  python operator_console.py list
  python operator_console.py show APR-0001
  python operator_console.py approve APR-0001 --role soc_operator --name "R. Nakamura" --note "OK"
  python operator_console.py deny APR-0001 --role soc_operator --name "R. Nakamura" --note "Wait"
  python operator_console.py audit --limit 20
  python operator_console.py verify
"""

import argparse
import json
import sys

from approvals import ApprovalService
from response_logic import ResponseError, Scenario


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Approve or deny response actions as a human operator.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="show all approvals")
    show = sub.add_parser("show", help="show one approval in full")
    show.add_argument("approval_id")
    for name in ("approve", "deny"):
        cmd = sub.add_parser(name, help=f"{name} a pending request")
        cmd.add_argument("approval_id")
        cmd.add_argument("--role", required=True, help="your role, e.g. soc_operator or ot_supervisor")
        cmd.add_argument("--name", required=True, help="your name, recorded in the audit log")
        cmd.add_argument("--note", help="optional comment")
    audit = sub.add_parser("audit", help="show recent audit entries")
    audit.add_argument("--limit", type=int, default=20)
    sub.add_parser("verify", help="check the audit log's hash chain")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = ApprovalService(Scenario())
    try:
        if args.command == "list":
            rows = service.list_approvals()
            if not rows:
                print("No approvals yet.")
            for r in rows:
                print(
                    f"{r['approval_id']}  {r['status']:<9} needs {r['required_role']:<13} {r['action']}:{r['target']}"
                )
        elif args.command == "show":
            print(json.dumps(service.status(args.approval_id), indent=2))
        elif args.command in ("approve", "deny"):
            result = service.decide(args.approval_id, args.command, args.role, args.name, args.note)
            print(f"{result['approval_id']} is now {result['status']} (by {args.name}, {args.role}).")
        elif args.command == "audit":
            for e in service.audit.read(args.limit):
                print(
                    f"{e['seq']:>3} {e['ts']} {e['event']:<28} {e['actor']}  "
                    f"{e.get('action', '')}:{e.get('target', '')}"
                )
        elif args.command == "verify":
            result = service.audit.verify()
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
    except ResponseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
