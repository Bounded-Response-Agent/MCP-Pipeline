"""Windows launcher for the local Bounded Response Agent console."""

import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import messagebox, ttk

from lab_backend import LabScenario
from response_logic import ResponseError

ROOT = Path(__file__).resolve().parent
URL = "http://127.0.0.1:8765"
HIDDEN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def command(args, **kwargs):
    return subprocess.run([str(value) for value in args], cwd=ROOT, creationflags=HIDDEN, **kwargs)


def python_for_console():
    for directory in (ROOT, ROOT.parent):
        candidate = directory / ".venv/Scripts/python.exe"
        if candidate.is_file() and command([candidate, "-c", "import mcp, starlette, uvicorn"],
                                           capture_output=True).returncode == 0:
            return candidate
    candidate = ROOT / ".venv/Scripts/python.exe"
    if not candidate.is_file():
        command([sys.executable, "-m", "venv", ROOT / ".venv"], check=True)
    command([candidate, "-m", "pip", "install", "-r", ROOT / "requirements.txt"], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return candidate


def configured_labs():
    choices = {}
    for path in sorted(ROOT.glob("*/config.json")):
        try:
            info = json.loads(path.read_text(encoding="utf-8"))
            if {"client_secret", "user_password", "state_dir"} <= info.keys():
                choices[path.parent.name] = path
        except (OSError, ValueError, AttributeError):
            continue
    return choices


def ready():
    try:
        with urllib.request.urlopen(URL + "/api/ai", timeout=1) as response:
            body = json.load(response)
            return "configured" in body and "operators_ready" in body
    except (OSError, ValueError):
        return False


def main():
    window = tk.Tk()
    window.title("Bounded Response Agent launcher")
    window.geometry("520x240")
    frame = ttk.Frame(window, padding=20)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Bounded Response Agent", font=("Segoe UI", 20, "bold")).pack(anchor="w")
    ttk.Label(frame, text="Choose the environment for this browser session.").pack(anchor="w", pady=(2, 10))
    labs = configured_labs()
    simulator, fresh = "Simulator", "Start a fresh shipboard live lab"
    enterprise = "Start a fresh enterprise live lab"
    mode = tk.StringVar(value=next(iter(labs), simulator))
    selection = ttk.Combobox(frame, textvariable=mode, state="readonly", values=[*labs, simulator, fresh, enterprise])
    selection.pack(fill="x")
    status = tk.StringVar(value="Podman is required for the live lab.")
    ttk.Label(frame, textvariable=status, wraplength=465).pack(anchor="w", pady=10)
    process = None

    def show(text, enabled=True):
        status.set(text)
        launch.configure(state="normal" if enabled else "disabled")

    def start(chosen):
        nonlocal process
        try:
            if ready():
                webbrowser.open(URL)
                window.after(0, show, "Opened the already-running console. Check its mode badge.")
                return
            python = python_for_console()
            env = os.environ.copy()
            env.pop("BRA_LAB_CONFIG", None)
            env.pop("BRA_WEB_CASE", None)
            if chosen != simulator:
                if command(["podman", "info"], capture_output=True).returncode:
                    command(["podman", "machine", "start"], check=True, capture_output=True)
                if chosen in (fresh, enterprise):
                    profile = "enterprise" if chosen == enterprise else "shipboard"
                    path = ROOT / f"lab-browser-{time.strftime('%Y%m%d-%H%M%S')}" / "config.json"
                    with (ROOT / "bounded-response-setup.log").open("w", encoding="utf-8") as log:
                        if command(["podman", "network", "exists", "bra-shipboard"], capture_output=True).returncode == 0:
                            raise RuntimeError("A live lab already exists. Choose its configuration or use Stop live lab first.")
                        command([python, "lab/stack.py", "start", "--config", path, "--profile", profile], stdout=log,
                                stderr=subprocess.STDOUT, check=True)
                        command([python, "lab/stack.py", "seed", "--profile", profile], stdout=log, stderr=subprocess.STDOUT, check=True)
                else:
                    path = labs[chosen]
                    if command(["podman", "inspect", "-f", "{{.State.Running}}", "bra-primary"],
                               capture_output=True, text=True).stdout.strip() != "true":
                        raise RuntimeError("That lab is stopped. Choose Start a fresh live lab.")
                    try:
                        LabScenario(json.loads(path.read_text(encoding="utf-8"))).identity()
                    except ResponseError as exc:
                        raise RuntimeError("This configuration does not match the running lab. Choose its current configuration.") from exc
                env["BRA_LAB_CONFIG"] = str(path)
            process = subprocess.Popen([str(python), str(ROOT / "web_console.py")], cwd=ROOT, env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=HIDDEN)
            for _ in range(30):
                if ready():
                    webbrowser.open(URL)
                    window.after(0, show, "Console opened. Closing this launcher stops the console.")
                    return
                if process.poll() is not None:
                    break
                time.sleep(0.5)
            raise RuntimeError("The console could not start. Check whether port 8765 is in use.")
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            message = str(exc) if isinstance(exc, RuntimeError) else (
                "Setup did not complete. Check Podman and bounded-response-setup.log if starting a live lab.")
            window.after(0, show, message)

    def launch_console():
        chosen = mode.get()
        show("Preparing Bounded Response Agent. The first launch may take a few minutes.", False)
        threading.Thread(target=start, args=(chosen,), daemon=True).start()

    def stop_lab():
        if not messagebox.askyesno("Stop lab", "Stop the Bounded Response Agent lab containers? Saved traces stay on disk."):
            return
        show("Stopping the lab…", False)

        def stop():
            try:
                command([python_for_console(), "lab/stack.py", "stop"], check=True, capture_output=True)
                window.after(0, show, "Lab stopped. Close and reopen the launcher to start a fresh exercise.")
            except (OSError, subprocess.SubprocessError):
                window.after(0, show, "Could not stop the lab. Check Podman.")
        threading.Thread(target=stop, daemon=True).start()

    def close():
        if process and process.poll() is None:
            process.terminate()
        window.destroy()

    launch = ttk.Button(frame, text="Open Bounded Response Agent", command=launch_console)
    launch.pack(side="left", anchor="n")
    ttk.Button(frame, text="Stop live lab", command=stop_lab).pack(side="left", anchor="n", padx=8)
    window.protocol("WM_DELETE_WINDOW", close)
    window.mainloop()


if __name__ == "__main__":
    main()
