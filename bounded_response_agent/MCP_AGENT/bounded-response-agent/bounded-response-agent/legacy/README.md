# Legacy demo: quarantine-only Bounded Response Agent

This is the original demo, kept as it was. It uses the first, simpler data set
(`legacy/data/`) and four tools: `lookup_device`, `get_events_for_ip`,
`summarize_denied_by_source` and `quarantine_host`. The main project has moved on to the
cooling-monitoring scenario in `data/v2/`; see the top-level README.

## Running the legacy demo
From the project folder, point the client at the legacy server:

```
# Windows (PowerShell)
.\.venv\Scripts\python.exe reset_demo.py
$env:BRA_SERVER = "legacy/server.py"
$env:LLM_API_KEY = "your-course-gateway-key"
.\.venv\Scripts\python.exe client.py "Which source IP has been hitting db01 with denied connections, and can you quarantine it?"

# macOS / Linux
.venv/bin/python reset_demo.py
export BRA_SERVER=legacy/server.py LLM_API_KEY="your-course-gateway-key"
.venv/bin/python client.py "Which source IP has been hitting db01 with denied connections, and can you quarantine it?"
```
Clear the variable afterwards with `Remove-Item Env:BRA_SERVER` (PowerShell) or
`unset BRA_SERVER`, or the client keeps using the legacy server.

Protocol check with no LLM: `.\.venv\Scripts\python.exe legacy/verify_tools.py`, then
`reset_demo.py` again, because that check quarantines `ws-bob`.

## Project description (original)
A small SOC (security operations center) assistant for a junior analyst. It can freely
investigate the network — look up devices and read firewall logs — but it is *bounded*
when it comes to taking action: it will only quarantine a host if that host is inside its
authorized response scope (`in_scope=true` in the inventory). Core infrastructure and
firewalls are outside that scope; the agent must refuse and say to escalate instead of
acting. This models the access-control idea that read authority and act authority can be
different boundaries, even for the same agent.

Data: `data/devices.csv` (a small inventory with an `in_scope` flag per device) and
`data/events.csv` (a firewall log). `data/actions_log.csv` ships with only its header
and records quarantine actions taken during a session.

A task that needs multiple tools: "investigate this IP's denied traffic, find out which
host it is, and quarantine it if you're allowed to" — one tool's output (the denied
source IP, or the resolved hostname) feeds the next tool's input.

## Tools
| Tool | Purpose | Bounded? | Validation |
|---|---|---|---|
| `lookup_device(hostname)` | Hostname -> IP, role, VLAN, in_scope | No (read) | Unknown host -> error |
| `get_events_for_ip(ip, action?, limit=20)` | Firewall events for an IP | No (read) | Valid IP, action in {allow, deny}, 1<=limit<=100 |
| `summarize_denied_by_source(min_count=1)` | Denied-connection counts per source IP | No (read) | min_count >= 1 |
| `quarantine_host(hostname, reason)` | The one response action: quarantine a device | **Yes** | Unknown host -> error; out-of-scope host -> refused with escalation message; empty reason -> error; repeat call -> idempotent, returns the original record instead of double-acting |

Errors are raised as `ToolError` (not plain `ValueError`) so the message reaches the
calling model — in SDK 2.x a plain `ValueError` is otherwise masked as a generic
"Error executing tool".


## Demonstration traces (fresh conversation each, same config)
Reset the action log before run A, then run each prompt in a fresh conversation:

```
# Windows (PowerShell)
.\.venv\Scripts\python.exe reset_demo.py
.\.venv\Scripts\python.exe client.py "<prompt>"

# macOS / Linux
.venv/bin/python reset_demo.py
.venv/bin/python client.py "<prompt>"
```

The client prints the MCP tool name, JSON arguments, returned result, and model text.
The protocol evidence below was captured with `verify_tools.py` and shows the
server-side calls and errors independently of an LLM. The final-answer text is
illustrative; capture actual model output by running the client with your gateway key.

**A. Successful task, dependent tool calls.**
Prompt: "Which source IP has been hitting db01 with denied connections, and can you
quarantine it?"
Expected shape: `lookup_device("db01")` -> `get_events_for_ip(ip="10.0.20.7", action="deny")`
or `summarize_denied_by_source` -> `lookup_device("ws-bob")` ->
`quarantine_host("ws-bob", reason)`.

Verified MCP call evidence:

```text
lookup_device({"hostname":"db01"}) -> {"hostname":"db01","ip":"10.0.20.7","role":"database","vlan":"20","in_scope":"true"}
get_events_for_ip({"ip":"10.0.20.7","action":"deny"}) -> four denied events from 10.0.30.22
lookup_device({"hostname":"ws-bob"}) -> {"ip":"10.0.30.22","in_scope":"true",...}
quarantine_host({"hostname":"ws-bob","reason":"repeated deny hits to db01"}) -> status=quarantined
```

Illustrative final answer (not a captured model run):

```text
Source IP: 10.0.30.22
Responsible host: ws-bob (in scope)

ws-bob generated denied traffic to db01 on ports 5432 and 22. It has been quarantined successfully.
```

**B. Different request, different tool combination.**
Prompt: "Is core-sw1 seeing any denied traffic, and would you be able to quarantine it if
needed?"
Expected shape: `lookup_device(core-sw1)` -> `get_events_for_ip` -> an attempted
`quarantine_host(core-sw1, ...)` that is refused for being out of scope, with the
assistant relaying the escalation message rather than claiming success.

Verified MCP call evidence:

```text
lookup_device({"hostname":"core-sw1"}) -> {"ip":"10.0.0.2","role":"core-switch","vlan":"0","in_scope":"false"}
get_events_for_ip({"ip":"10.0.0.2"}) -> []
quarantine_host({"hostname":"core-sw1","reason":"test out-of-scope refusal"}) -> ERROR: outside authorized response scope; escalate to a senior analyst
```

Illustrative final answer (not a captured model run):

```text
core-sw1 has no denied firewall events. It is a core switch and outside the agent's quarantine scope, so it was not quarantined; escalate to a senior analyst if containment is required.
```

**C. Invalid input / failed call, handled without inventing success.**
Prompt: "Quarantine the host printer07, it looks suspicious."
Expected shape: `quarantine_host(printer07, ...)` (or a `lookup_device` first) returns a
"no device named" error; the assistant reports that printer07 isn't in the inventory and
does not claim it was quarantined.

Verified MCP call evidence:

```text
lookup_device({"hostname":"printer07"}) -> ERROR: No device named 'printer07'
```

Illustrative final answer (not a captured model run):

```text
Unable to quarantine printer07: it is not present in the authorized device inventory, so no action was taken.
```

## Architecture (150-250 words)
The MCP server owns the security data and the operations that may be performed on it. It
loads the device inventory and firewall events, validates typed tool arguments, exposes
the investigation tools, and enforces the response boundary inside `quarantine_host`.
That rule is authoritative: the server refuses out-of-scope infrastructure even if the
model requests the action. The MCP client is the host application. It starts the server
over stdio, initializes an MCP session, discovers the available tools and JSON schemas,
translates those schemas for Gemini, and sends the user's goal to the model. When Gemini
returns a function call, the client invokes that named tool through MCP, prints the
result, and sends the result back into the conversation. It repeats this loop until the
model produces a final response. The LLM interprets the natural-language goal, chooses
a tool and arguments, reads returned data, decides whether another call is needed, and
composes the final answer. In run A, for example, the model can use the database and
denied-event results to select the workstation for quarantine.

One limitation observed is that the server's scope is a single boolean per device. It
can distinguish readable and actionable devices, but cannot express finer permissions
such as allowing event collection while forbidding only one kind of response action.
Cover: what the MCP server owns (tool implementations, data, the scope/validation rules),
what the MCP client does (the host app: discovers tools via MCP, sends the schema to the
model, executes whichever calls the model requests, returns results to the model), and
what the LLM does (reads the user's goal, decides which tools to call and in what order,
reads each result before deciding the next call, composes the final answer). Note that
tool authority (like the in_scope boundary) is enforced by the server, not by asking the
model nicely — the model can request `quarantine_host` on anything, but only the server
decides whether it happens.

## Limitation observed
The model may call `quarantine_host` directly when a hostname is already present in the
prompt instead of first calling `lookup_device`. This is acceptable because the server
performs the authoritative existence and scope checks, but it can make the investigation
trace less informative than a cautious analyst workflow.

