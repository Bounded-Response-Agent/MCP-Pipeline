"""Scoped firewall drivers for the isolated lab workstation namespace."""

import json
import shlex

from response_logic import ResponseError


class NftablesFirewall:
    def __init__(self, invoke):
        self.invoke = invoke

    def rules(self, execution_id):
        rules = json.loads(self.invoke("nft", "-j", "-a", "list", "chain", "inet", "bra", "output"))
        return [row["rule"]["handle"] for row in rules["nftables"]
                if "rule" in row and row["rule"].get("comment") == execution_id]

    def apply(self, execution_id, ports, *, isolate=False):
        if self.rules(execution_id):
            return
        if isolate:
            rule = ["oifname", "!=", "lo", "ip", "daddr", "!=", "10.245.77.31", "counter", "drop"]
        else:
            destination = str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(map(str, ports)) + " }"
            rule = ["ip", "daddr", "10.245.77.20", "tcp", "dport", destination, "counter", "drop"]
        self.invoke("nft", "insert" if isolate else "add", "rule", "inet", "bra", "output",
                    *rule, "comment", execution_id)

    def rollback(self, execution_id):
        for handle in self.rules(execution_id):
            self.invoke("nft", "delete", "rule", "inet", "bra", "output", "handle", str(handle))


class IptablesFirewall:
    def __init__(self, invoke):
        self.invoke = invoke

    def rules(self, execution_id):
        result = []
        for line in self.invoke("iptables", "-w", "2", "-S", "BRA-RESPONSE").splitlines():
            fields = shlex.split(line)
            if fields[:2] == ["-A", "BRA-RESPONSE"] and "--comment" in fields:
                if fields[fields.index("--comment") + 1] == execution_id:
                    result.append(fields[2:])
        return result

    def apply(self, execution_id, ports, *, isolate=False):
        if isolate:
            raise ResponseError("This firewall profile only supports scoped flow controls.")
        if not self.rules(execution_id):
            self.invoke("iptables", "-w", "2", "-A", "BRA-RESPONSE", "-d", "10.245.77.20",
                        "-p", "tcp", "-m", "multiport", "--dports", ",".join(map(str, ports)),
                        "-m", "comment", "--comment", execution_id, "-j", "DROP")

    def rollback(self, execution_id):
        for rule in self.rules(execution_id):
            self.invoke("iptables", "-w", "2", "-D", "BRA-RESPONSE", *rule)
