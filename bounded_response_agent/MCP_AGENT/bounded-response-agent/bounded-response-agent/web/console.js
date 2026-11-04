"use strict";

const $ = id => document.getElementById(id);
const labels = {
  continue_monitoring: "Continue monitoring", block_network_flow: "Block network flow",
  restrict_network_flow: "Restrict selected flow", disable_account: "Disable account",
  isolate_endpoint: "Isolate workstation", failover_to_backup: "Transition to backup"
};
let token, caseScope = "", cases = [], decision, aiTimer, displayedEvents = 0, displayedRun = null, approvalKey, inlineKey;
let conversationKey, pickerOpen = false, activityKey, selectedAction;

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}
function addButton(target, title, handler, cls) {
  const button = el("button", title, cls);
  button.type = "button";
  button.addEventListener("click", handler);
  target.append(button);
}
function detail(value) {
  return el("pre", JSON.stringify(value, null, 2));
}
function list(value) {
  return Array.isArray(value) ? value : value?.result || [];
}
function message(value, error = false) {
  $("message").textContent = value;
  $("message").className = error ? "alert" : "";
}
async function post(operation, body) {
  const response = await fetch("/api/" + operation, {
    method: "POST", headers: {"Content-Type": "application/json", "X-Operator-Token": token, "X-Case-Scope": caseScope},
    body: JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "The request failed.");
  return result;
}
async function apply(operation, body) {
  try {
    message("Working…");
    const result = await post(operation, body);
    message(result.verified !== undefined
      ? result.verified ? "Verification passed." : "Verification did not pass. Review the audit trail."
      : "Outcome · " + (result.status || result.verdict || "recorded"));
    await refresh(false);
  } catch (error) { message(error.message, true); }
}
function showDecision(operation, approval) {
  decision = {operation, approval_id: approval.approval_id, execution_id: approval.execution_id};
  $("operator-form").reset();
  $("decision-title").textContent = ({
    approve: "Approve this action", deny: "Deny this action", "authorize-rollback": "Authorize scoped rollback"
  })[operation];
  $("decision-target").textContent = approval.approval_id + " · " + labels[approval.action] + " · " + approval.target +
    " · Required role " + approval.required_role;
  $("operator-form").elements.note.required = operation === "authorize-rollback";
  $("decision-error").textContent = "";
  $("decision").showModal();
}

function showOptions(data) {
  $("recommendation").replaceChildren();
  $("choices").replaceChildren();
  const plan = data.plans?.recommended_plan;
  if (plan) {
    const card = el("div", undefined, "callout");
    card.append(el("strong", "Recommended plan"));
    card.append(el("p", plan.steps.length
      ? plan.steps.map(step => labels[step.action] + " " + step.target).join(" → ")
      : "Continue monitoring. No observed attack path currently requires a change."));
    card.append(el("small", "Projected residual paths: " + (plan.projected_residual.join(", ") || "none") +
      " · Disruption score " + plan.disruption_score));
    $("recommendation").append(card);
  } else $("recommendation").append(el("p", data.plans?.error || "No effective plan is currently safe."));
  const alternate = el("details");
  alternate.append(el("summary", "View projected plan impacts and residual risk"),
    detail(data.plans?.alternatives || []));
  $("choices").append(alternate);
  const options = data.options?.options || [];
  for (const option of options) {
    const row = el("div", undefined, "row");
    const info = el("div");
    info.append(el("strong", labels[option.action] + (option.target ? " · " + option.target : "")));
    info.append(el("small", option.verdict.replaceAll("_", " ") + " · Mission impact " +
      option.mission_severity + " · " + option.reason));
    row.append(info);
    if (option.verdict === "allowed" && option.approval_required) {
      addButton(row, "Request approval", () => apply("request", {
        action: option.action, target: option.target,
        rationale: "Operator reviewed the defensive action and mission impact in the response console."
      }));
    }
    $("choices").append(row);
  }
  if (!options.length) $("choices").append(el("p", data.options?.error || "No options are available."));
}

function showApprovals(data) {
  const approvals = list(data.approvals);
  const key = JSON.stringify([approvals.map(item => [item.approval_id, item.status, item.execution_status]), data.approvals?.error]);
  if (key === approvalKey) return;
  approvalKey = key;
  const pendingCount = approvals.filter(item => item.status === "pending").length;
  $("approval-summary").textContent = pendingCount ? pendingCount + " pending approval" + (pendingCount === 1 ? "" : "s")
    : "All approvals and execution results";
  $("queue").replaceChildren();
  if (!approvals.length) $("queue").append(el("p", data.approvals?.error || "No approval requests yet."));
  for (const approval of approvals) {
    const row = el("div", undefined, "row");
    const info = el("div");
    info.append(el("strong", approval.approval_id + " · " + labels[approval.action] + " · " + approval.target));
    info.append(el("small", approval.status + (approval.execution_status ? " → " + approval.execution_status : "") +
      " · Required role " + approval.required_role));
    const plan = el("details");
    plan.append(el("summary", "Reviewed impact and recovery"), detail({
      rationale: approval.rationale, target: approval.target, role: approval.required_role,
      impact: approval.plan.mission_impact, changes: approval.plan.predicted_state_changes,
      recovery: approval.plan.automatic_recovery, plan_hash: approval.plan_hash
    }));
    info.append(plan);
    const buttons = el("div", undefined, "buttons");
    if (approval.status === "pending") {
      addButton(buttons, "Approve", () => showDecision("approve", approval), "primary");
      addButton(buttons, "Deny", () => showDecision("deny", approval));
    } else if (approval.valid_for_execution) {
      addButton(buttons, "Execute", () => apply("execute", {approval_id: approval.approval_id}), "primary");
    }
    if (approval.execution_id) {
      addButton(buttons, "Verify", () => apply("verify", {execution_id: approval.execution_id}));
      if (approval.execution_status !== "rolled_back") {
        addButton(buttons, "Authorize rollback", () => showDecision("authorize-rollback", approval));
        addButton(buttons, "Run rollback", () => apply("rollback", {execution_id: approval.execution_id}));
      }
    }
    row.append(info, buttons);
    $("queue").append(row);
  }
}

async function refresh(announce = true) {
  $("refresh").disabled = true;
  if (announce) message("Refreshing case…");
  try {
    const response = await fetch("/api/dashboard", {cache: "no-store"});
    if (!response.ok) throw new Error("The MCP console is unavailable.");
    const data = await response.json();
    token = data.token;
    if (caseScope !== (data.scope || "")) {
      displayedRun = null;
      displayedEvents = 0;
      refreshedOutcomes = null;
      inlineKey = null;
      approvalKey = null;
      activityKey = null;
      selectedAction = null;
      conversationKey = null;
      $("ai-prompt").reset();
      $("ai-events").replaceChildren();
      $("ai-approval").replaceChildren();
    }
    caseScope = data.scope || "";
    renderCasePicker(data.cases || [], data.active_case);
    showIntake(data.intake || [], data.live_intake);
    $("case-content").hidden = !data.active_case;
    $("switch-case").hidden = !data.active_case;
    $("case-picker").hidden = Boolean(data.active_case) && !pickerOpen;
    $("case-title").textContent = data.active_case?.title || "No active incident";
    if (!data.active_case) {
      $("mode").textContent = "Choose an environment";
      $("case").textContent = "CASE WORKSPACE";
      $("summary").textContent = "Open a built-in incident or import a SOC handoff to get started.";
      if (announce) message("");
      return;
    }
    $("health-label").textContent = data.active_case.health_label;
    $("source-label").textContent = data.active_case.source_label;
    $("mode").textContent = data.environment?.mode || "Unknown mode";
    $("case").textContent = data.findings?.case_id || "SHIPBOARD EXERCISE";
    $("summary").textContent = data.findings?.summary || data.findings?.error || "No active findings.";
    $("findings").replaceChildren(detail(data.findings));
    const health = data.outcomes?.cooling;
    const probes = data.outcomes?.probes;
    $("health").textContent = health ? health.healthy ? "Healthy" : "Action needed" : "Unavailable";
    $("health").className = health?.healthy ? "good" : "warn";
    $("gap").textContent = health?.max_gap_s == null ? data.outcomes?.error || "No verified gap"
      : health.max_gap_s + " s observed gap / " + health.limit_s + " s limit";
    $("source").textContent = health?.source || "—";
    $("paths").textContent = probes ? Object.values(probes).filter(probe => probe.allowed > 0).length : "—";
    $("probes").textContent = probes ? Object.keys(probes).length + " attack paths checked" : "No observations";
    showOptions(data);
    showApprovals(data);
    await refreshActivity();
    $("integrity").textContent = data.audit_integrity?.ok ? "Hash chain verified" : "Audit integrity unavailable";
    const audit = list(data.audit);
    $("events").replaceChildren();
    for (const event of [...audit].reverse()) {
      const item = el("details");
      item.append(el("summary", event.ts + " · " + event.event.replaceAll("_", " ") + " · " + event.actor), detail(event));
      $("events").append(item);
    }
    if (!audit.length) $("events").append(el("p", data.audit?.error || "No decisions recorded yet."));
    if (announce) message("");
    if (!aiTimer) await refreshAI();
  } catch (error) { message(error.message, true); }
  finally { $("refresh").disabled = false; }
}

$("refresh").addEventListener("click", () => refresh());
$("cancel").addEventListener("click", () => $("decision").close());
$("operator-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('[type="submit"]');
  submit.disabled = true;
  try {
    const {operation, ...fields} = decision;
    const result = await post(operation, {...fields, ...Object.fromEntries(new FormData(form))});
    $("decision").close();
    message("Operator decision · " + result.status);
    await refreshApprovals();
    await refreshActivity();
    await refreshAI();
  } catch (error) { $("decision-error").textContent = error.message; }
  finally { form.elements.passphrase.value = ""; submit.disabled = false; }
});
async function refreshApprovals() {
  const response = await fetch("/api/approvals", {cache: "no-store"});
  if (response.ok) {
    const approvals = await response.json();
    showApprovals({approvals});
    return list(approvals);
  }
  return [];
}

function renderAI(data) {
  $("ai-connection").textContent = data.configured ? data.model + " · key set" : "Setup required";
  $("operator-setup").hidden = data.operators_ready;
  const run = data.run;
  $("ai-prompt").querySelector("button").disabled = !data.configured || run?.status === "running";
  const history = data.history || [];
  renderConversation(history);
  $("ai-export").hidden = history.length === 0;
  $("ai-export").href = "/api/conversation?scope=" + encodeURIComponent(caseScope);
  if (!run) {
    $("ai-activity").hidden = true;
    $("ai-status").textContent = "";
    return;
  }

  const id = run.id;
  if (id !== displayedRun) {
    $("ai-events").replaceChildren();
    displayedEvents = 0;
    displayedRun = id;
  }
  $("ai-activity").hidden = run.events.length === 0;
  const messages = {
    running: "The assistant is working. An approval request will appear here.",
    completed: "Run complete.",
    max_turns_exceeded: "The run reached its tool-call limit. Review any pending approvals.",
    failed: "Run failed.",
    interrupted: "Run interrupted."
  };
  $("ai-status").textContent = run.error || messages[run.status];
  for (const event of run.events.slice(displayedEvents)) {
    if (event.kind === "tool_call" || event.kind === "tool_result") {
      const item = el("details");
      item.append(el("summary", event.kind === "tool_call" ? "Called " + event.name :
        event.name + " · " + event.status), detail(event.arguments ?? event.text));
      $("ai-events").append(item);
    }
  }
  displayedEvents = run.events.length;
}

function addInline(parent, value, depth = 0) {
  if (depth >= 3) {
    parent.append(document.createTextNode(value));
    return;
  }
  const tokens = /`([^`\n]+)`|\*\*([^\n]+?)\*\*|\*([^*\n]+)\*/g;
  let end = 0;
  for (const match of value.matchAll(tokens)) {
    parent.append(document.createTextNode(value.slice(end, match.index)));
    const node = el(match[1] ? "code" : match[2] ? "strong" : "em");
    if (match[1]) node.textContent = match[1];
    else addInline(node, match[2] || match[3], depth + 1);
    parent.append(node);
    end = match.index + match[0].length;
  }
  parent.append(document.createTextNode(value.slice(end)));
}

function renderReply(value) {
  const blocks = [];
  const lines = value.replaceAll("\r\n", "\n").split("\n");
  const listMarker = /^(\d+\.|[-+*])\s+(.*)$/;
  const heading = /^#{1,6}\s+(.*)$/;
  const separator = /^(?:-{3,}|\*{3,}|_{3,})$/;
  const isQuote = line => /^>\s?/.test(line);
  const cells = line => line.replace(/^\||\|$/g, "").split(/(?<!\\)\|/)
    .map(cell => cell.trim().replaceAll("\\|", "|"));
  function tableAt(index) {
    const first = lines[index]?.trim();
    const second = lines[index + 1]?.trim();
    if (!first?.includes("|") || !second?.includes("|")) return false;
    const markers = cells(second);
    return markers.length > 1 && markers.length === cells(first).length &&
      markers.every(marker => /^:?-{3,}:?$/.test(marker));
  }

  let index = 0;
  while (index < lines.length) {
    const line = lines[index].trim();
    if (!line || separator.test(line)) {
      index++;
    } else if (line.startsWith("```")) {
      const content = [];
      index++;
      while (index < lines.length && !lines[index].trim().startsWith("```")) content.push(lines[index++]);
      if (index < lines.length) index++;
      const pre = el("pre");
      pre.append(el("code", content.join("\n")));
      blocks.push(pre);
    } else if (tableAt(index)) {
      const header = cells(line);
      const table = el("table");
      const head = table.createTHead().insertRow();
      for (const column of header) {
        const cell = el("th");
        cell.scope = "col";
        addInline(cell, column);
        head.append(cell);
      }
      const body = table.createTBody();
      index += 2;
      while (index < lines.length && lines[index].trim() && lines[index].includes("|")) {
        const columns = cells(lines[index++].trim());
        const row = body.insertRow();
        header.forEach((_, column) => addInline(row.insertCell(), columns[column] || ""));
      }
      const wrapper = el("div", undefined, "reply-table");
      wrapper.append(table);
      blocks.push(wrapper);
    } else if (heading.test(line)) {
      const title = el("h3");
      addInline(title, line.match(heading)[1]);
      blocks.push(title);
      index++;
    } else if (listMarker.test(line)) {
      const ordered = /^\d/.test(line);
      const list = el(ordered ? "ol" : "ul");
      if (ordered) list.start = Number(line.match(/^\d+/)[0]);
      while (index < lines.length) {
        const item = lines[index].trim().match(listMarker);
        if (!item || /^\d/.test(item[1]) !== ordered) break;
        const child = el("li");
        addInline(child, item[2]);
        list.append(child);
        index++;
      }
      blocks.push(list);
    } else if (isQuote(line)) {
      const quote = el("blockquote");
      while (index < lines.length && isQuote(lines[index].trim())) {
        const text = el("p");
        addInline(text, lines[index++].trim().replace(/^>\s?/, ""));
        quote.append(text);
      }
      blocks.push(quote);
    } else {
      const paragraph = el("p");
      addInline(paragraph, line);
      blocks.push(paragraph);
      index++;
    }
  }

  const reply = el("div", undefined, "reply");
  if (value.length > 1200 && blocks.length > 3) {
    const split = blocks[2].tagName === "H3" ? 2 : 3;
    const extra = el("details", undefined, "reply-extra");
    extra.append(el("summary", "Show full reply"), ...blocks.slice(split));
    reply.append(...blocks.slice(0, split), extra);
  } else reply.append(...blocks);
  return reply;
}

function renderConversation(turns) {
  const key = JSON.stringify(turns.map(turn => [turn.id, turn.status, turn.answer, turn.error]));
  if (key === conversationKey) return;
  conversationKey = key;
  const chat = $("conversation");
  const atBottom = chat.scrollHeight - chat.scrollTop - chat.clientHeight < 32;
  chat.replaceChildren();
  if (!turns.length) {
    chat.append(el("p", "Start a conversation about this incident. The assistant can inspect the evidence, compare responses, or explain a previous decision."));
    return;
  }
  function addTurn(role, text, style) {
    const bubble = el("article", undefined, "chat-turn " + style);
    bubble.append(el("strong", role), role === "Assistant" && style === "assistant-turn"
      ? renderReply(text) : el("div", text));
    chat.append(bubble);
  }
  for (const turn of turns) {
    addTurn("You", turn.goal, "user-turn");
    if (turn.answer) addTurn("Assistant", turn.answer, "assistant-turn");
    else if (turn.status === "running") addTurn("Assistant", "Working on your request…", "assistant-turn");
    else addTurn("Run status", turn.error || "No answer was returned for this turn.", "assistant-turn");
  }
  if (atBottom) chat.scrollTop = chat.scrollHeight;
}

async function refreshAI() {
  clearTimeout(aiTimer);
  aiTimer = null;
  try {
    const response = await fetch("/api/ai", {cache: "no-store"});
    const data = await response.json();
    if (data.scope !== caseScope) return;
    renderAI(data);
    const run = data.run;
    const card = $("ai-approval");
    const approvalEvents = (run?.events || []).filter(event => event.kind === "approval");
    const ids = new Set(approvalEvents.map(event => event.approval.approval_id));
    const approvals = ids.size && run.status === "running" ? await refreshApprovals() : [];
    const pending = approvals.filter(item => ids.has(item.approval_id) && item.status === "pending");
    const key = pending.map(item => item.approval_id).join(",");
    if (inlineKey !== key) {
      inlineKey = key;
      card.replaceChildren();
      for (const approval of pending) {
        const entry = el("div", undefined, "callout");
        entry.append(el("strong", approval.approval_id + " · " + labels[approval.action] + " · " + approval.target));
        entry.append(el("p", "Required role " + approval.required_role + ". " + approval.rationale));
        const review = el("details");
        review.append(el("summary", "Review exact changes, mission impact, and recovery"),
          detail({changes: approval.plan.predicted_state_changes,
            impact: approval.plan.mission_impact, recovery: approval.plan.automatic_recovery}));
        entry.append(review);
        const buttons = el("div", undefined, "buttons");
        addButton(buttons, "Approve", () => showDecision("approve", approval), "primary");
        addButton(buttons, "Deny", () => showDecision("deny", approval));
        entry.append(buttons);
        card.append(entry);
      }
    }
    if (run?.status === "running") {
      await refreshActivity();
      aiTimer = setTimeout(refreshAI, 1500);
    }
    else if (run && run.id !== refreshedOutcomes) {
      refreshedOutcomes = run.id;
      await refresh(false);
    }
  } catch (error) { $("ai-status").textContent = error.message; }
}

let refreshedOutcomes = null;
for (const [formId, operation] of [["ai-config", "ai-configure"], ["ai-prompt", "ai-run"],
                                   ["operator-config", "provision-operators"]]) {
  $(formId).addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      await post(operation, Object.fromEntries(new FormData(form)));
      if (operation === "ai-run") form.reset();
      await refreshAI();
      if (operation === "ai-configure") $("ai-status").textContent = "Key set for this session. Run a prompt to verify access.";
    } catch (error) { $("ai-status").textContent = error.message; }
    finally {
      for (const field of form.querySelectorAll('input[type="password"]')) field.value = "";
      if (operation !== "ai-run") submit.disabled = false;
      else {
        const response = await fetch("/api/ai", {cache: "no-store"}).catch(() => null);
        if (response?.ok) {
          const state = await response.json();
          submit.disabled = !state.configured || state.run?.status === "running";
        } else submit.disabled = false;
      }
    }
  });
}
$("ai-disconnect").addEventListener("click", async () => {
  try {
    await post("ai-disconnect", {});
    await refreshAI();
  } catch (error) { $("ai-status").textContent = error.message; }
});
function showIntake(entries, live) {
  $("scan-intake").hidden = !live;
  const queue = $("intake-queue");
  queue.replaceChildren();
  if (!entries.length) {
    queue.append(el("p", live ? "Check the connected Suricata sensor or import a SOC handoff."
      : "Import a SOC handoff to add an incident for review."));
    return;
  }
  for (const entry of entries) {
    const row = el("div", undefined, "row");
    const info = el("div");
    info.append(el("strong", entry.title), el("small", entry.status + " · " + entry.case_id));
    const evidence = el("details");
    evidence.append(el("summary", "Intake evidence"));
    for (const event of entry.evidence) {
      evidence.append(el("p", [event.source, event.asset, event.destination, event.latest]
        .filter(Boolean).join(" · ")), el("small", event.signature + (event.count ? " · " + event.count + " alerts" : "")));
    }
    info.append(evidence);
    row.append(info);
    addButton(row, entry.status === "Needs review" ? "Open for review" : "Open incident",
      () => openCase(entry.key).catch(error => message(error.message, true)));
    queue.append(row);
  }
}

async function refreshActivity() {
  const scope = caseScope;
  if (!scope) return;
  const response = await fetch("/api/activity", {cache: "no-store"});
  const data = await response.json();
  if (caseScope !== scope || (data.scope && data.scope !== scope)) return;
  const actions = data.actions || [];
  const key = JSON.stringify(actions) + (data.error || "");
  if (key === activityKey) return;
  activityKey = key;
  showActivity(actions, data.error);
}

function showActivity(actions, error) {
  const panel = $("action-activity");
  panel.replaceChildren();
  if (!actions.length) {
    panel.append(el("p", error || "Action milestones will appear here after a proposal."));
    return;
  }
  const active = actions.find(action => action.id === selectedAction) || actions[0];
  const picker = el("label", "Action timeline");
  const select = el("select");
  for (const action of actions) {
    const option = el("option", (labels[action.action] || action.action) + " · " + (action.target || "—") +
      " · " + action.stages.at(-1).label);
    option.value = action.id;
    select.append(option);
  }
  select.value = active.id;
  select.addEventListener("change", () => { selectedAction = select.value; showActivity(actions); });
  picker.append(select);
  panel.append(picker);
  const card = el("article", undefined, "verification-card");
  card.append(el("strong", active.stages.at(-1).label));
  if (active.operator) card.append(el("small", "Operator " + active.operator.replaceAll(":", " · ")));
  const timeline = el("ol", undefined, "action-timeline");
  for (const step of active.stages) {
    const item = el("li");
    const label = el("span", step.label);
    label.title = new Date(step.time).toLocaleString();
    item.append(label);
    if (step.detail) item.append(el("small", step.detail));
    timeline.append(item);
  }
  card.append(timeline);
  if (active.after) {
    const before = active.before;
    const after = active.after;
    const showPaths = after.probes?.[active.target] ? [active.target]
      : Object.keys(after.probes || {}).filter(target => before?.probes?.[target]?.allowed !== after.probes[target].allowed);
    const outcome = el("div", undefined, "outcome-compare");
    const probeText = probe => probe ? (probe.allowed ? "Allowed" : "Blocked") +
      " (" + probe.allowed + "/" + probe.hostile_attempts + ")" : "Unavailable";
    const healthText = check => {
      if (!check) return "Unavailable";
      const gap = check.transition_gap_s ?? check.max_gap_s;
      return (check.healthy ? "Healthy" : "Unhealthy") + (gap == null ? "" :
        " · " + gap + " s / " + check.limit_s + " s");
    };
    const addComparison = (title, start, end) => {
      const row = el("div");
      row.append(el("small", title), el("span", start + " → " + end));
      outcome.append(row);
    };
    for (const target of showPaths) {
      addComparison(target + " hostile probe", probeText(before?.probes?.[target]), probeText(after.probes[target]));
    }
    addComparison("Protected service", healthText(before?.cooling), healthText(after.cooling));
    card.append(outcome);
    if (!before) card.append(el("small", "This historical execution predates baseline capture."));
    if (active.recovery) {
      const recovery = active.recovery;
      const preserved = Object.keys(recovery.probes || {}).filter(target => target !== active.target &&
        before?.probes?.[target]?.allowed === 0 && recovery.probes[target].allowed === 0);
      const restored = (recovery.restored || []).map(change => change.key);
      if (restored.length) card.append(el("p", "Reversed changes · " + restored.join(", ")));
      if (preserved.length) card.append(el("p", "Other paths still blocked · " + preserved.join(", ")));
      if (recovery.cooling) card.append(el("p", "After recovery · " + healthText(recovery.cooling)));
    }
  }
  panel.append(card);
}

async function openCase(key) {
  await post("select-case", {case: key});
  pickerOpen = false;
  await refresh();
}

$("scan-intake").addEventListener("click", async () => {
  $("scan-intake").disabled = true;
  try {
    const result = await post("scan-intake", {});
    await refresh(false);
    message(result.new_groups ? "New Suricata evidence is ready for review."
      : result.alerts_added ? "Additional related Suricata alerts recorded." : "No new matching Suricata alerts.");
  } catch (error) { message(error.message, true); }
  finally { $("scan-intake").disabled = false; }
});

function renderCasePicker(items, active) {
  const previous = $("case-environment").value;
  cases = items;
  const environments = new Map(items.map(item => [environmentKey(item), item.environment + " · " + item.mode]));
  $("case-environment").replaceChildren(...[...environments].map(([key, name]) => {
    const option = el("option", name);
    option.value = key;
    return option;
  }));
  if (environments.has(previous)) $("case-environment").value = previous;
  else if (active) $("case-environment").value = environmentKey(active);
  updateCaseChoices(active?.key);
}
function environmentKey(item) { return item.profile + "|" + item.mode; }
function updateCaseChoices(current) {
  const select = $("case-selection");
  const previous = current || select.value;
  select.replaceChildren(...cases.filter(item => environmentKey(item) === $("case-environment").value).map(item => {
    const option = el("option", item.title + " · " + item.case_id);
    option.value = item.key;
    return option;
  }));
  if ([...select.options].some(option => option.value === previous)) select.value = previous;
}
$("case-environment").addEventListener("change", () => updateCaseChoices());
$("case-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  try {
    await openCase($("case-selection").value);
  } catch (error) { message(error.message, true); }
  finally { button.disabled = false; }
});
$("case-import").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const [profile, mode] = $("case-environment").value.split("|");
    if (mode !== "simulator") throw new Error("Choose a simulator environment to import a SOC handoff.");
    const incident = JSON.parse(event.currentTarget.elements.incident.value);
    const result = await post("import-case", {profile, incident});
    await refresh(false);
    $("case-selection").value = result.case;
    message("Incident imported. Select Open incident to begin.");
  } catch (error) { message(error.message, true); }
});

$("switch-case").addEventListener("click", () => {
  pickerOpen = !pickerOpen;
  $("case-picker").hidden = !pickerOpen;
  if (pickerOpen) $("case-environment").focus();
});
for (const id of ["options", "audit"]) {
  document.querySelector('nav a[href="#' + id + '"]')?.addEventListener("click", () => { $(id).open = true; });
}

refresh();
