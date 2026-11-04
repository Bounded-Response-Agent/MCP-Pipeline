# Bounded Response Agent

A browser-based operator console and MCP service for the simulated shipboard cooling incident. The console is served on loopback and uses the same planning, approval, execution, verification, and audit workflow as the MCP client.

## Workspaces

Bounded Response Agent opens with **No active incident**. Select an environment and incident, then click **Open incident**.

| Environment | Built-in case | Protected function | Live firewall |
| --- | --- | --- | --- |
| Shipboard OT | Engineering workstation compromise | Cooling telemetry, 120-second gap limit | nftables |
| Enterprise commerce | Suspected credential theft on order-processing host | Checkout availability, 30-second gap limit | iptables |

The simulator offers both profiles immediately. For a live lab, choose the matching running configuration in the launcher or start a fresh lab for that profile. The configured live workspace appears in the browser picker alongside the simulator profiles. To switch between live profiles, stop the existing lab and start the other profile from the launcher. This preserves the two exercises' separate state and audit records.

The **Import a SOC handoff into the simulator** panel accepts a JSON incident for a selected simulator profile. Use `data/enterprise/sample-soc-handoff.json` as an example. Imports can describe findings and refer to inventory already in the environment. Trusted profile files control policies, mission dependencies, telemetry, and the actuator allowlist. Imports are simulator-only in this release.

Cases use dedicated MCP sessions, approval stores, and audit logs. A pending approval or an active AI run blocks switching. Approval fingerprints bind the case and environment workspace as well as the policy, target, and reviewed action. Existing pending approvals from versions before environment scoping must be requested again. The case picker rejects stale browser actions after a switch.

### Intake and response evidence

From **Open an incident**, use **Check Suricata alerts** when a live lab is connected. Bounded Response Agent reads the current alerts via MCP, groups repeated alerts by signature and lab destination, and links supported evidence to the configured live incident. A new group or imported SOC handoff is marked **Needs review**. Opening it changes the review state to **Opened**. Intake is on demand, and opening a case grants no action approval.

In **Response and approvals**, the **Action timeline** shows recorded milestones from proposal and authorization through application, verification, or recovery. Newly executed actions record a baseline before applying the change and compare it with the verification probes afterward. A successful configuration write and successful verification appear separately. The card reports mission telemetry against the case's limit and shows whether other blocked paths remained blocked after recovery. Older executions show that baseline data is unavailable when it was never recorded.

### Add another environment

Create a trusted profile directory with the same inventory, mission dependency, policy, telemetry, and findings files. Register it in `profiles.py`. The profile identifies the service to observe, the poll interval, and any disruption penalties. For live execution, bind only supported targets to the environment's connectors, declare those targets in the policy scope, and test the applied change, outcome probes, and rollback together. Each bundled profile designates one protected service for continuous outcome checks. Other modeled dependencies are evaluated during impact analysis.

### Verify generalization

- `python verify_case_workflow.py` runs both browser/MCP AI workflows using a scripted gateway and checks incident selection, validated import, case switching, and approval isolation.
- Start a fresh live lab and run `python demo_live.py --config <path-to-config.json>` to exercise that profile through the browser service and MCP. The enterprise exercise tests scoped iptables changes, credential containment, checkout telemetry, stale-telemetry refusal, and rollback. The shipboard exercise tests nftables, approved failover, recovery, and endpoint isolation.

## Browser demo on Windows

Double-click **Launch Bounded Response Agent.cmd**. Choose the configuration for the running lab (such as `lab-ai`), **Simulator**, or a fresh shipboard or enterprise live lab. If an older lab is still running, you can inspect it or use **Stop live lab** before starting a fresh one. Keep the launcher open while using the console. Windows Python is required. The launcher sets up the virtual environment when needed. Podman is required for the live lab.

1. Open an incident, then open **Settings → Configure course gateway access**, enter your course API key, and select **Set up gateway**. The default model is `gpt-oss-120b`. A prompt run verifies the credentials. The local backend holds the key in memory for the session. It sends the key to the course gateway at `https://128.171.10.83:9443/v1` over HTTPS and excludes it from the downloadable trace.
2. Expand **Set up operator identities** if prompted. Create separate SOC watch and OT supervisor passphrases. Existing operator credentials continue to work.
3. Enter a prompt, leave **Recommend only** selected, and select **Send**. The response and MCP tool activity appear in the browser.
4. For the execution exercise, use a fresh live lab and choose **Request containment**. Ask the assistant to check the evidence for blocking F004 (shipboard) or WEB004 (enterprise), request approval for that action only, wait for the decision, and verify both traffic and cooling afterward. Review the inline request and authenticate as **SOC watch** to approve it. The AI can then call the execution tool. The MCP server verifies the approval and live preconditions.
5. Reply in the same **Incident conversation**. Bounded Response Agent saves messages, replies, and tool traces in a local SQLite database inside the case state directory. Reopen the same incident after restarting to continue. The API key must be entered again.

The conversation displays the latest 100 turns and passes up to eight completed turns from the same incident to the model, within a 24,000-character context budget. Earlier messages provide context. Tool results and approvals must be checked for the current turn. Use **Evidence, MCP activity, and audit → Download conversation and AI traces** for the complete saved record. Browser conversations are separate by case and environment. They are shared by people using the same local console and case.

## Run the console on Windows

From this folder:

```powershell
py -3 -m venv .venv
$python = ".\.venv\Scripts\python.exe"
& $python -m pip install -r requirements.txt
& $python operator_console.py provision
& $python web_console.py
```

Open **http://127.0.0.1:8765** and select an incident. Provisioning gives separate passphrases to the SOC operator and the OT supervisor. Keep the passphrases and the generated operator file private. The first run uses the built-in simulator. The console displays its active mode at the top.

In **Response options**, review the recommendation and request approval for one action at a time. In **Operator approvals**, expand the reviewed impact, then approve or deny with the assigned operator identity. Choose **Execute** after approval. The outcome cards and audit show whether the control applied, whether the targeted activity stopped, and which cooling poller is healthy. To reverse an applied action intentionally, choose **Authorize rollback**, record the reason, then choose **Run rollback**.

## Run with five real integrations

Install Podman and start its machine on Windows. The lab starts on an internal Podman network. Its APIs are published only to loopback, and all test traffic and control changes are confined to the lab containers. The build uses Debian packages and pinned OPA, Keycloak, and Prometheus images. Use the default ports or make sure they are available before startup.

```powershell
& $python lab/stack.py start --config lab-state/config.json
& $python lab/stack.py seed
$env:BRA_LAB_CONFIG = (Resolve-Path lab-state/config.json).Path
& $python web_console.py
```

Run the console from a shell that has `BRA_LAB_CONFIG` set. Open the same local URL, select the live incident, and confirm the **live lab** badge. Shut down the console with Ctrl+C. Run `& $python lab/stack.py stop` to remove this lab's containers and network. For a fresh exercise use a new configuration directory when starting the stack again. The generated configuration contains lab-only credentials and stays outside the submission.

| Integration | Role in the exercise |
| --- | --- |
| **Suricata** | Inspects real packet traffic on the workstation's lab interface. The evidence view includes EVE alert timestamps, flow IDs, destination ports, and signature IDs. Flow changes require recent matching alerts. |
| **Open Policy Agent** | Evaluates the site action allowlist, policy verdict, and observed cooling preconditions at proposal, approval, and execution. The audit records the policy result and revision. |
| **nftables** | Applies real kernel firewall rules inside the workstation network namespace. The scoped restriction preserves the separate legitimate application path. Isolation preserves the monitoring management path. Rollback removes only the action's named rule. |
| **Keycloak** | Disables the suspected lab user and logs out its sessions. The agent checks fresh login and an already-issued refresh token. Re-enabling the account restores its ability to log in. Terminated sessions require a new login. |
| **Prometheus** | Scrapes successful cooling-poll timestamps from both pollers. The agent uses fresh samples to verify containment and failover. During failover the primary continues polling until the backup has a verified sample. |

The lab workload represents the protected service and attack paths. It uses harmless HTTP requests as stand-ins for cooling or checkout and suspicious outbound traffic. The two profiles use different firewall command interfaces. Debian iptables uses the nft compatibility backend in this lab. The firewall, detection engine, policy engine, identity service, and time-series database are real. Lab mode uses those services for policy and observations. It surfaces service failures and holds potentially uncertain writes for operator review.

### Run the reproducible live exercise

Start a **fresh** lab, then run:

```powershell
& $python demo_live.py --config lab-state/config.json --output live-trace.json
```

The runner drives the web service and its MCP connection with temporary scripted operator identities. It does not need an AI gateway. It checks unsafe isolation and protected-flow refusal, approved targeted containment, a real firewall precedence conflict, a silent-backup condition, scoped recovery, verified failover, and authorized isolation. It leaves the lab in its final containment state. For a classroom presentation, use the browser and have the operator make the decisions.

### Verify the simulator separately

```powershell
& $python data/v2/validate_data.py
& $python -m unittest -v test_response_logic test_approvals
& $python demo_mcp.py --output simulator-trace.json
```

The optional model client uses the same MCP service. Set `LLM_API_KEY` to your course key. The CLI uses the course gateway and `gpt-oss-120b` by default. `LLM_BASE_URL` and `LLM_MODEL` override those defaults when set. Use `client.py --execute` to permit the model to request and execute approved actions. Operator approval remains separate.

## Trust boundary

The console is a local application for the isolated exercise. The operating system account and Podman engine administer the lab. Use the web operator form or the terminal operator console to authenticate decisions. MCP exposes proposals and execution of authorized actions. Every live mutation stays in the dedicated lab namespace and identity realm. For an uncertain result, inspect the audit log and actual control state before resuming. A recorded hold requires reconciliation or a fresh lab.
