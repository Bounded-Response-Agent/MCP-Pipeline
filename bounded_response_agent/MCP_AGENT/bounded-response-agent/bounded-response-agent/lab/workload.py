"""HTTP endpoints and cooling pollers for the simulated shipboard environment."""

import os
import sys
import time
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PREFIX = os.environ.get("BRA_LAB_SUBNET_PREFIX", "10.245.77")
PLC = f"http://{PREFIX}.20:8001/cooling"
TARGETS = {
    "F004": f"http://{PREFIX}.20:8004/c2",
    "F005": f"http://{PREFIX}.20:8005/lateral",
    "F006": f"http://{PREFIX}.20:8006/lateral",
    "legitimate": f"http://{PREFIX}.20:8007/engineering",
    "cooling": PLC,
}


def reachable(url):
    try:
        with urllib.request.urlopen(url, timeout=0.7) as response:
            return response.status == 200
    except OSError:
        return False


def run(mode):
    last_poll = 0
    active = Path("/tmp/poll-active")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/metrics" and mode == "poller":
                data = f"bra_cooling_active {int(active.exists())}\nbra_cooling_last_poll_seconds {last_poll:.3f}\n"
            elif mode == "target":
                data = "simulated lab workload\n"
            else:
                self.send_error(404)
                return
            body = data.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    ports = (9100,) if mode == "poller" else (8001, 8004, 8005, 8006, 8007)
    for port in ports:
        server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        if mode == "poller" and active.exists() and not Path("/tmp/poll-silent").exists() and reachable(PLC):
            last_poll = time.time()
        time.sleep(0.75)


if __name__ == "__main__":
    if sys.argv[1] == "probe":
        print(int(reachable(TARGETS[sys.argv[2]])))
    else:
        run(sys.argv[1])
