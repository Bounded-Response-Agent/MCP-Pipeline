"""Start and stop the isolated shipboard lab with Podman."""

import argparse
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SLOTS = {"default": ("bra-", "10.245.77", {"opa": 18181, "prometheus": 19090, "keycloak": 18080}),
         "test": ("bra-test-", "10.245.78", {"opa": 28181, "prometheus": 29090, "keycloak": 28080})}
SLOT = os.environ.get("BRA_LAB_SLOT", "default")
CONTAINER_PREFIX, SUBNET_PREFIX, PORTS = SLOTS[SLOT]
NETWORK = CONTAINER_PREFIX + "shipboard"
IMAGE = "localhost/bra-lab-workload:1"
CONTAINERS = ("bra-primary", "bra-backup", "bra-target", "bra-opa", "bra-prometheus", "bra-keycloak")


def pod(*arguments, check=True, timeout=90, slot=SLOT):
    prefix = SLOTS[slot][0]
    names = {name: prefix + name[4:] for name in CONTAINERS}
    translated = []
    for argument in map(str, arguments):
        head, separator, tail = argument.partition(":")
        translated.append(names.get(head, head) + separator + tail)
    arguments = translated
    try:
        result = subprocess.run(["podman", *map(str, arguments)], capture_output=True,
                                text=True, timeout=timeout, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Podman {arguments[0]} could not complete.") from exc
    if result.returncode and check:
        raise RuntimeError(f"Podman {arguments[0]} failed: {result.stderr.strip()}")
    return result.stdout if check else result


def wait_url(url, limit=120):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return response.status
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"Lab service did not become ready: {url}")


def stop():
    for name in CONTAINERS:
        if pod("container", "exists", name, check=False).returncode:
            continue
        label = pod("inspect", "--format", '{{index .Config.Labels "bra.lab"}}', name).strip()
        if label != "shipboard":
            raise RuntimeError(f"{name} is not owned by this lab.")
        pod("rm", "-f", "--time", "1", name)
    if not pod("network", "exists", NETWORK, check=False).returncode:
        label = pod("network", "inspect", "--format", '{{index .Labels "bra.lab"}}', NETWORK).strip()
        if label != "shipboard":
            raise RuntimeError(f"{NETWORK} is not owned by this lab.")
        pod("network", "rm", NETWORK)


def create(name, ip, image, command, *, files=(), port=None, extra=()):
    options = ["--name", name, "--label", "bra.lab=shipboard", "--network", NETWORK, "--ip", f"{SUBNET_PREFIX}.{ip}"]
    if port:
        options += ["-p", f"127.0.0.1:{port[0]}:{port[1]}"]
    if image == IMAGE:
        options += ["-e", f"BRA_LAB_SUBNET_PREFIX={SUBNET_PREFIX}"]
    pod("create", *options, *extra, image, *command, timeout=600)
    for source, target in files:
        pod("cp", source, f"{name}:{target}")
    pod("start", name)


def lab_profile(profile):
    directory = {"shipboard": "v2", "enterprise": "enterprise"}[profile]
    return json.loads((ROOT.parent / "data" / directory / "profile.json").read_text(encoding="utf-8"))["lab"]


def start(config, profile="shipboard"):
    binding = lab_profile(profile)
    if config.exists():
        raise RuntimeError("Use a new lab configuration path. Run stop before creating a fresh lab.")
    if not pod("network", "exists", NETWORK, check=False).returncode:
        raise RuntimeError("The lab network already exists. Reuse the running lab or stop it explicitly.")
    subprocess.run(["podman", "build", "-t", IMAGE, "-f", str(ROOT / "Containerfile"), str(ROOT)], check=True)
    pod("network", "create", "--internal", "--label", "bra.lab=shipboard", "--subnet", f"{SUBNET_PREFIX}.0/24", NETWORK)
    create("bra-target", 20, IMAGE, ["python3", "/lab/workload.py", "target"])
    create("bra-backup", 11, IMAGE, ["python3", "/lab/workload.py", "poller"])
    create("bra-primary", 10, IMAGE, ["python3", "/lab/workload.py", "poller"], extra=("--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"))
    pod("exec", "bra-primary", "touch", "/tmp/poll-active")
    if binding["firewall"] == "iptables":
        pod("exec", "bra-primary", "iptables", "-N", "BRA-RESPONSE")
        pod("exec", "bra-primary", "iptables", "-A", "OUTPUT", "-j", "BRA-RESPONSE")
    else:
        pod("exec", "bra-primary", "nft", "add", "table", "inet", "bra")
        pod("exec", "bra-primary", "nft", "add", "chain", "inet", "bra", "output",
            "{ type filter hook output priority 0; policy accept; }")
    pod("exec", "bra-primary", "suricata", "-D", "-i", "eth0", "--runmode", "single", "-S", "/lab/detection.rules",
        "-l", "/tmp", "-k", "none", "--set", "app-layer.protocols.http.enabled=yes")
    create("bra-opa", 30, "docker.io/openpolicyagent/opa:1.4.2",
           ["run", "--server", "--addr", "0.0.0.0:8181", "--log-level", "error", "/response.rego"],
           files=[(ROOT / "response.rego", "/response.rego")], port=(PORTS["opa"], 8181))
    with tempfile.TemporaryDirectory() as directory:
        prometheus = Path(directory) / "prometheus.yml"
        prometheus.write_text((ROOT / "prometheus.yml").read_text(encoding="utf-8").replace(
            "10.245.77", SUBNET_PREFIX), encoding="utf-8")
        create("bra-prometheus", 31, "docker.io/prom/prometheus:v3.4.1",
               ["--config.file=/etc/prometheus/lab.yml", "--storage.tsdb.retention.time=1d"],
               files=[(prometheus, "/etc/prometheus/lab.yml")], port=(PORTS["prometheus"], 9090))
    config.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        realm = Path(directory) / "bra-realm.json"
        client_secret, user_password = (secrets.token_urlsafe(24) for _ in range(2))
        realm.write_text(json.dumps({
            "realm": "bra", "enabled": True,
            "clients": [
                {"clientId": "bra-admin", "secret": client_secret, "publicClient": False,
                 "serviceAccountsEnabled": True, "standardFlowEnabled": False},
                {"clientId": "bra-login", "publicClient": True, "directAccessGrantsEnabled": True,
                 "standardFlowEnabled": False}
            ],
            "users": [
                {"username": "service-account-bra-admin", "enabled": True, "serviceAccountClientId": "bra-admin",
                 "clientRoles": {"realm-management": ["manage-users", "view-users"]}},
                {"username": binding["account"], "enabled": True, "firstName": "Engineering", "lastName": "Lab",
                 "email": "engineering@example.invalid", "credentials": [{"type": "password", "value": user_password}]}
            ],
        }), encoding="utf-8")
        create("bra-keycloak", 32, "quay.io/keycloak/keycloak:26.2.5",
               ["-c", "mkdir -p /opt/keycloak/data/import && cp /tmp/bra-realm.json /opt/keycloak/data/import/"
                " && exec /opt/keycloak/bin/kc.sh start-dev --import-realm --http-enabled=true --hostname-strict=false"],
               files=[(realm, "/tmp/bra-realm.json")], port=(PORTS["keycloak"], 8080),
               extra=("--entrypoint", "/bin/bash", "-e", "JAVA_OPTS_KC_HEAP=-Xms128m -Xmx512m"))
    wait_url(f"http://127.0.0.1:{PORTS['opa']}/health")
    wait_url(f"http://127.0.0.1:{PORTS['prometheus']}/-/ready")
    wait_url(f"http://127.0.0.1:{PORTS['keycloak']}/realms/bra/.well-known/openid-configuration")
    with config.open("x", encoding="utf-8") as file:
        json.dump({"profile": profile, "slot": SLOT, "client_secret": client_secret, "user_password": user_password,
                   "state_dir": str(config.parent.resolve() / "response-state")}, file)
    print("Lab ready. Set BRA_LAB_CONFIG to the configuration path and launch web_console.py.")


def seed(profile="shipboard"):
    """Send only harmless synthetic traffic inside the lab to exercise Suricata."""
    ports = set(lab_profile(profile)["flow_ports"].values())
    probes = {8004: "F004", 8005: "F005", 8006: "F006"}
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        for port in sorted(ports):
            pod("exec", "bra-primary", "python3", "/lab/workload.py", "probe", probes[port])
        output = pod("exec", "bra-primary", "tail", "-n", "200", "/tmp/eve.json", check=False)
        alerts = [json.loads(line) for line in output.stdout.splitlines() if line.startswith("{")]
        if ports <= {alert.get("dest_port") for alert in alerts if alert.get("event_type") == "alert"}:
            print("Suricata observed the selected lab traffic fixtures.")
            return
        time.sleep(1)
    raise RuntimeError("Expected Suricata alerts were not observed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "seed", "stop"))
    parser.add_argument("--config", type=Path, default=Path("lab-state/config.json"))
    parser.add_argument("--profile", choices=("shipboard", "enterprise"), default="shipboard")
    args = parser.parse_args()
    if args.command == "start":
        start(args.config, args.profile)
    elif args.command == "seed":
        seed(args.profile)
    else:
        stop()
