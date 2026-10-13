# Bounded Response Agent

## What this is
A cyber-response agent that proposes containment actions in a simulated shipboard
enterprise and OT environment, and is *bounded*: policy, mission impact and human approval
decide what it may do, not the model. The goal is to contain an attack without causing
unacceptable mission or safety consequences.

**Scenario (`data/v2/`).** The SOC Investigation Agent reports that engineering workstation
`ws-eng01` is very likely compromised. It beacons to an external host, moved 310 MB out,
tries to spread over SMB and RDP, and holds a stolen `eng.mokoa` credential. It also runs
the polling client for shipboard cooling monitoring. Isolating it would stop the spread but
open a telemetry gap longer than the 120 s limit, unless monitoring is first failed over to
the standby `backup-mon01`. The agent must compare the options and recommend the least
disruptive effective one.

## Status
| Step | Capability | State |
|---|---|---|
| 1 | Scenario data, policy model | Done (`data/v2/`) |
| 2 | Read and analysis tools: policy, mission impact, dry-run simulation | **Done (this version)** |
| 3 | Approval requests and audit log | Planned |
| 4 | Execution tools, post-action verification, rollback | Planned |
| 5 | Full demo traces and tests for the refusal and rollback paths | Planned |

All tools are read-only today. The agent can recommend; it cannot execute anything yet.

The original quarantine-only demo is kept in [`legacy/`](legacy/README.md).

## Tools
| Tool | Purpose |
|---|---|
| `get_investigation_findings` | The SOC findings: claims, confidence, evidence, affected assets, accounts and flows |
| `get_response_policy` | Per-action disruption rank, approval role, forbidden conditions, preconditions, rollback |
| `get_events` | The event timeline behind the findings (EDR, firewall, identity), filterable by host, source, severity, action and time |
| `lookup_device`, `lookup_account` | Inventory facts, including `protected` and `revocable_by_agent` |
| `get_network_flows` | Flows with purpose, status and whether mission critical |
| `get_system_health` | Telemetry used for preconditions |
| `get_mission_dependencies` | What each mission function needs, primary or backup, plus its gap limit |
| `analyze_mission_impact` | Predicts which functions an action interrupts and for how long |
| `simulate_response` | Dry run: policy, preconditions, evidence, impact, approval level and a verdict |
| `list_response_options` | Simulates every candidate, ranked least to most disruptive, and reports threats only a blocked option could address |

`simulate_response` verdicts: `allowed`, `forbidden`, `insufficient_evidence`,
`unacceptable_impact`, `preconditions_not_met`. `assume_done` (for example
`["failover_to_backup:cooling_monitoring"]`) lets the agent evaluate a sequence, such as
failover first and then isolation.

Errors are raised as `ToolError` so the message reaches the model.

## Layout
- `server.py`: MCP server exposing the tools.
- `response_logic.py`: the analysis logic, plain Python so it is testable without MCP.
- `client.py`: the MCP host and agent loop (OpenAI-compatible gateway).
- `data/v2/`: scenario files. `scenario_ground_truth.json` is for tests only; the agent never reads it.
- `test_response_logic.py`: unit tests. `verify_tools.py`: protocol check over MCP, no LLM.
- `legacy/`: the original demo.

## Setup
Requires Python 3.10 or newer. From this folder, create a virtual environment and install
the pinned MCP dependency.

**Windows (PowerShell):**
```
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**macOS / Linux:**
```
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## Check it works
```
# Windows (PowerShell)
.\.venv\Scripts\python.exe -m unittest -v test_response_logic   # logic tests, no MCP needed
.\.venv\Scripts\python.exe verify_tools.py                      # every tool over MCP, no LLM

# macOS / Linux
.venv/bin/python -m unittest -v test_response_logic
.venv/bin/python verify_tools.py
```

## Run the agent
Set the course gateway key in your shell. The project does not include a key. The client
uses `https://128.171.10.83:9443/v1` by default; set `LLM_BASE_URL` to override it and
`LLM_MODEL` to choose another model. It prints every tool call, its arguments, the raw
result and the final answer.

```
# Windows (PowerShell)
$env:LLM_API_KEY = "your-course-gateway-key"
.\.venv\Scripts\python.exe client.py "The SOC says ws-eng01 may be compromised. What should we do?"

# macOS / Linux
export LLM_API_KEY="your-course-gateway-key"
.venv/bin/python client.py "The SOC says ws-eng01 may be compromised. What should we do?"
```

Other prompts to try:
- "Should we isolate ws-eng01 right now?" (expect: not yet, failover first)
- "What if we fail over cooling monitoring first, then isolate ws-eng01?"
- "Disable the adm.kealoha account." (expect: refused, escalate)
- "Block the cooling telemetry flow F001." (expect: refused, mission critical)

VS Code (`.vscode/mcp.json`) and Claude Desktop (`claude_desktop_config.example.json`) can
also connect to `server.py`. The VS Code config uses the Windows project virtual
environment; change `command` to `${workspaceFolder}/.venv/bin/python` on macOS or Linux.

## Demonstration plan
1. **Least disruptive effective response.** Investigate, simulate, reject isolation because of the cooling gap, recommend block F004, restrict F005 and F006, disable `eng.mokoa`.
2. **Contingency.** Failover with supervisor approval, verify, then isolate `ws-eng01`.
3. **Refusals.** Protected device, privileged account, mission-critical flow, no approval.
4. **Rollback.** An action fails verification or is reversed.

Demos 1 and 2 can be shown as recommendations now. Demos 3 and 4 need steps 3 and 4.
Capture real traces by running the client; do not paste illustrative output as captured.

## Architecture
The MCP server owns the data and the rules. It loads the findings, inventory, flows,
mission dependencies, health telemetry and policy, and exposes read and analysis tools.
Authority lives there: simulation marks a protected device, a privileged account or a
mission-critical flow as forbidden whatever the model asks, and later steps will enforce
approval and verification the same way. The client is the host. It starts the server over
stdio, discovers the tools, passes their JSON schemas to the model, runs the calls the model
requests, and feeds the results back until the model answers. The model reads the goal,
chooses tools, reads each result before the next call, and writes the recommendation.
The model proposes; the server decides.

## Known limitations
- Policy is data in `policy.json`, and the evidence rule is simple: an action needs a threat finding at or above the confidence threshold that names its target.
- Impact analysis treats a restricted flow like a blocked one (worst case) and reports an unbounded gap until failover completes, since failover needs supervisor approval.
- Scenario names and IPs are invented.
