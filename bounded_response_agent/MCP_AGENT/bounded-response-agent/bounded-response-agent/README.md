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
| --- | --- | --- |
| 1 | Scenario data, policy model | Done (`data/v2/`) |
| 2 | Read and analysis tools: policy, mission impact, dry-run simulation | Done |
| 3 | Human approval and tamper-evident audit log | **Done (this version)** |
| 4 | Execution tools, post-action verification, rollback | Done (simulated state) |
| 5 | Full demo traces and tests for the refusal and rollback paths | In progress |

The agent can recommend, obtain human approval, execute approved actions against simulated
state, verify the result, and roll back the simulated change. It does not control real
firewalls, identities, or endpoints.

For an external demonstration, a local REST test environment is available in
`test_environment.py`. It is disabled by default. Start it in one terminal:

```shell
.\.venv\Scripts\python.exe test_environment.py
```

Copy the printed URL and enable the explicit test-only adapter in the shell running the
agent:

```powershell
$env:BRA_EXECUTION_MODE = "external-test"
$env:BRA_ENVIRONMENT = "test"
$env:BRA_EXTERNAL_BASE_URL = "http://127.0.0.1:PORT"
```

Only an approved `block_network_flow` action for test flow `F004` is accepted by this
environment. The adapter sends the approval ID with the request, verifies the returned
execution, and supports rollback. Do not point these variables at production services.

The decision posture is defensive:

- `APPROVED`: a state-changing request was approved by the required human role.
- `PENDING_APPROVAL`: a state-changing action passed the dry run but still needs a human
  decision.
- `BLOCKED`: policy, evidence, preconditions, mission impact, role, expiry, or another
  authority check prevents the action.

`APPROVED` means authorized or ready for execution in this version; it does not claim that
an external production system was changed. Execution is limited to simulated state or the
explicitly opt-in local REST test environment.

The original quarantine-only demo is kept in [`legacy/`](legacy/README.md).

## Tools

| Tool | Purpose |
| --- | --- |
| `get_investigation_findings` | The SOC findings: claims, confidence, evidence, affected assets, accounts and flows |
| `get_response_policy` | Per-action disruption rank, approval role, forbidden conditions, preconditions, rollback |
| `get_events` | The event timeline behind the findings (EDR, firewall, identity), filterable by host, source, severity, action and time |
| `lookup_device`, `lookup_account` | Inventory facts, including `protected` and `revocable_by_agent` |
| `get_network_flows` | Flows with purpose, status and whether mission critical |
| `get_system_health` | Telemetry used for preconditions |
| `get_mission_dependencies` | What each mission function needs, primary or backup, plus its gap limit |
| `analyze_mission_impact` | Predicts which functions an action interrupts and for how long |
| `simulate_response` | Dry run: policy, preconditions, evidence, impact, approval level and a verdict |
| `evaluate_response_request` | Defensive gate: returns `REJECTED`, `HUMAN_REVIEW`, or `APPROVED` with an explanation and next step |
| `evaluate_investigation_response` | Derives response candidates from the current investigation findings and applies the defensive gate to each |
| `list_response_options` | Simulates every candidate, ranked least to most disruptive, and reports threats only a blocked option could address |

`simulate_response` verdicts: `allowed`, `forbidden`, `insufficient_evidence`,
`unacceptable_impact`, `preconditions_not_met`. `assume_done` (for example
`["failover_to_backup:cooling_monitoring"]`) lets the agent evaluate a sequence, such as
failover first and then isolation.

Approval and audit tools:

| Tool | Purpose |
| --- | --- |
| `request_operator_approval` | Ask a human to approve one action. The action is dry-run first; the request is refused unless the verdict is `allowed`. Creates a pending request only; nothing is executed |
| `get_approval_status`, `wait_for_approval`, `list_approvals` | Read an approval's status: pending, approved, denied or expired |
| `get_audit_log`, `verify_audit_log` | Read the audit log and check its hash chain |
| `execute_approved_action` | Execute a still-valid approved plan against simulated state and verify it |
| `verify_system_state` | Re-check the simulated state for an execution |
| `rollback_action` | Restore the captured pre-action simulated state |

There is deliberately no tool that approves or denies. See "Approval and audit" below.

Errors are raised as `ToolError` so the message reaches the model.

## Layout

- `server.py`: MCP server exposing the analysis, approval and live integration tools.
- `response_logic.py`: the analysis logic, plain Python so it is testable without MCP.
- `approvals.py`: approval records and the audit log, also plain Python.
- `operator_console.py`: the human's tool for approving and denying.
- `client.py`: the MCP host and agent loop (OpenAI-compatible gateway).
- `data/v2/`: scenario files. `scenario_ground_truth.json` is for tests only; the agent never reads it.
- `test_response_logic.py`, `test_approvals.py`: unit tests. `verify_tools.py`: protocol check over MCP, no LLM.
- `state/`: approvals and the audit log at run time (git-ignored; `reset_demo.py` clears it).
- `legacy/`: the original demo.

## Setup

Requires Python 3.10 or newer. From this folder, create a virtual environment and install
the pinned MCP dependency.

**Windows (PowerShell):**

```shell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**macOS / Linux:**

```shell
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## Check it works

```shell
# Windows (PowerShell)
.\.venv\Scripts\python.exe -m unittest -v test_response_logic test_approvals   # logic tests, no MCP needed
.\.venv\Scripts\python.exe verify_tools.py                      # every tool over MCP, no LLM

# macOS / Linux
.venv/bin/python -m unittest -v test_response_logic test_approvals
.venv/bin/python verify_tools.py
```

## Run the agent

Set the course gateway key in your shell. The project does not include a key. The client
uses `https://128.171.10.83:9443/v1` by default; set `LLM_BASE_URL` to override it and
`LLM_MODEL` to choose another model. It prints every tool call, its arguments, the raw
result and the final answer. To read the goal from JSON and save a structured JSON result,
use `--input` and `--output`. The input file must contain a string `goal` property:

```json
{
  "goal": "Investigate ws-eng01 and recommend the least disruptive response."
}
```

```shell
# Windows (PowerShell)
$env:LLM_API_KEY = "your-course-gateway-key"
.\.venv\Scripts\python.exe client.py "The SOC says ws-eng01 may be compromised. What should we do?"
.\.venv\Scripts\python.exe client.py --input request.json --output response.json

# macOS / Linux
export LLM_API_KEY="your-course-gateway-key"
.venv/bin/python client.py "The SOC says ws-eng01 may be compromised. What should we do?"
.venv/bin/python client.py --input request.json --output response.json
```

The output JSON contains the goal, server name, discovered tools, every tool call and
result, the final answer, and a run status (`completed` or `max_turns_exceeded`).

When the agent requests approval, the client pauses and asks you to approve or deny it, so
you play the human operator. Use `$env:BRA_MAX_TURNS` to raise the agent's turn limit (default 25).

Other prompts to try:

- "Recommend a response to the ws-eng01 incident and request approval for each step."- "Should we isolate ws-eng01 right now?" (expect: not yet, failover first)
- "What if we fail over cooling monitoring first, then isolate ws-eng01?"
- "Disable the adm.kealoha account." (expect: refused, escalate)
- "Block the cooling telemetry flow F001." (expect: refused, mission critical)

VS Code (`.vscode/mcp.json`) and Claude Desktop (`claude_desktop_config.example.json`) can
also connect to `server.py`. The VS Code config uses the Windows project virtual
environment; change `command` to `${workspaceFolder}/.venv/bin/python` on macOS or Linux.

## Approval and audit

The agent proposes and a human decides.

1. The agent calls `request_operator_approval`. The server dry-runs the action and refuses
   it unless the verdict is `allowed`. Otherwise it writes a pending approval bound to the
   case, action and target, with the required role (`soc_operator`, or `ot_supervisor` when a
   safety-critical function is involved) and a fingerprint of the plan the human is shown.
2. A human decides. When `client.py` runs in a terminal it stops and asks you. Or run
   `operator_console.py` in a second terminal (for example
   `operator_console.py approve APR-0001 --role soc_operator --name "Your Name"`). The role
   you give must be at least the required role, or the decision is rejected and logged.
3. The agent reads the result with `wait_for_approval`. A pending request lapses after 900 s;
   an approval is valid for 900 s from the decision. Expired approvals cannot be used.

The model has no tool to approve or deny, so it cannot approve its own request. A test
checks that `server.py` never exposes one.

Every request, refusal, decision, rejected decision and expiry is appended to
`state/audit.jsonl`. Each entry includes the hash of the previous one, so editing, removing,
reordering or splicing in an entry is detected by `verify_audit_log` or
`operator_console.py verify`. This makes tampering evident; it does not prevent someone with
file access who rebuilds the whole chain, so keep a copy of the latest `head_hash` if that
matters.

## Demonstration plan

1. **Least disruptive effective response.** Investigate, simulate, reject isolation because of the cooling gap, recommend block F004, restrict F005 and F006, disable `eng.mokoa`.
2. **Contingency.** Failover with supervisor approval, verify, then isolate `ws-eng01`.
3. **Refusals.** Protected device, privileged account, mission-critical flow, no approval.
4. **Rollback.** An action fails verification or is reversed.

Demos 1 and 2 can be shown now as recommendations with real approvals. The refusal demo
works today for policy refusals and for expired, under-privileged or repeated approvals.
Execution-related refusals and rollback need step 4.
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
- The audit log is tamper-evident, not tamper-proof (see above).
- Approvals are recorded, but nothing consumes them yet. Step 4 will check an approval's action, target, expiry and plan fingerprint again at execution time.
- Scenario names and IPs are invented.
