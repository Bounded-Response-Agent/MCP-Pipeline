"""Trusted local operator console for the simulator."""

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path

from approvals import ApprovalService
from lab_backend import load_lab
from profiles import scenario_from_environment
from response_logic import ResponseError, Scenario


OPERATORS = {"soc-watch": "soc_operator", "ot-watch": "ot_supervisor"}


def credential(password: str, salt: str) -> str:
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()


def provision(path: Path, passwords: dict[str, str]) -> None:
    if set(passwords) != OPERATORS.keys() or any(len(password) < 12 for password in passwords.values()):
        raise ResponseError("Each operator needs a passphrase of at least 12 characters.")
    if len(set(passwords.values())) != len(passwords):
        raise ResponseError("Use different passphrases for the two roles.")
    records = {}
    for identity, password in passwords.items():
        salt = secrets.token_hex(16)
        records[identity] = {"salt": salt, "digest": credential(password, salt)}
    with path.open("x", encoding="utf-8") as file:
        json.dump(records, file, indent=2)


def authenticate(path: Path, identity: str, password: str) -> str:
    records = json.loads(path.read_text(encoding="utf-8"))
    entry = records.get(identity)
    if identity not in OPERATORS or not entry or not hmac.compare_digest(
        credential(password, entry["salt"]), entry["digest"]
    ):
        raise ResponseError("Operator authentication failed.")
    return OPERATORS[identity]


def read_passphrase(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline().rstrip("\r\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("provision", help="assign separate credentials to the preassigned simulator roles")
    sub.add_parser("list")
    show = sub.add_parser("show")
    show.add_argument("approval_id")
    for name in ("approve", "deny", "authorize-rollback"):
        command = sub.add_parser(name)
        command.add_argument("reference")
        command.add_argument("--operator", required=True, choices=OPERATORS)
        command.add_argument("--note", required=name == "authorize-rollback")
    sub.add_parser("audit")
    sub.add_parser("verify")
    args = parser.parse_args()
    lab = load_lab()
    service = ApprovalService(lab or scenario_from_environment(), lab.lab["state_dir"] if lab else None)
    path = Path(os.environ.get("BRA_OPERATOR_FILE", "operators.local.json"))
    try:
        if args.command == "provision":
            passwords = {}
            for identity, role in OPERATORS.items():
                password = read_passphrase(f"New passphrase for {identity} ({role}): ")
                if read_passphrase("Confirm passphrase: ") != password:
                    raise ResponseError("Passphrases differ.")
                passwords[identity] = password
            provision(path, passwords)
            result = {"operators": OPERATORS}
        elif args.command == "list":
            result = service.list_approvals()
        elif args.command == "show":
            result = service.status(args.approval_id)
        elif args.command == "audit":
            result = service.audit.read(limit=200)
        elif args.command == "verify":
            result = service.audit.verify()
        else:
            role = authenticate(path, args.operator, read_passphrase("Operator passphrase: "))
            if args.command == "authorize-rollback":
                service.authorize_rollback(args.reference, role, args.operator, args.note)
                result = {"execution_id": args.reference, "status": "rollback_authorized"}
            else:
                result = service.decide(args.reference, args.command, role, args.operator, args.note)
        print(json.dumps(result, indent=2))
        return int(args.command == "verify" and not result["ok"])
    except (ResponseError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
