"""Local web operator console. MCP owns agent tools; the operator channel owns decisions."""

import argparse
import json
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import uvicorn
from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from case_workspace import CaseCatalog
from incident_intake import ingest_suricata, queue_entries, review
from response_activity import response_activity
from operator_console import authenticate, provision
from response_logic import ResponseError

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
CSRF = secrets.token_urlsafe(32)


@asynccontextmanager
async def lifespan(app):
    catalog = app.state.catalog = CaseCatalog()
    initial = os.environ.get("BRA_WEB_CASE")
    if initial:
        await select_case(catalog, initial)
    try:
        yield
    finally:
        for workspace in catalog.items.values():
            await workspace.close()


async def call_mcp(workspace, tool, args=None):
    result = await workspace.session.call_tool(tool, args or {})
    body = "\n".join(block.text for block in result.content if hasattr(block, "text"))
    if result.is_error:
        raise ResponseError(body)
    return result.structured_content if result.structured_content is not None else json.loads(body)


async def select_case(catalog, key):
    if key not in catalog.items:
        raise ResponseError("Select a listed incident.")
    if catalog.active and catalog.active.key == key:
        if catalog.active.live or catalog.active.case_file:
            await anyio.to_thread.run_sync(review, catalog.active)
        return catalog.active.summary()
    previous = catalog.active
    settings = None
    if previous:
        agent = previous.agent
        if agent.task and not agent.task.done():
            raise ResponseError("Wait for the current AI run to finish before switching incidents.")
        approvals = await call_mcp(catalog.active, "list_approvals", {"status": "pending"})
        if approvals["result"]:
            raise ResponseError("Decide pending approvals in this incident before switching.")
        settings = agent.settings
    workspace = catalog.items[key]
    await workspace.connect()
    if workspace.live or workspace.case_file:
        await anyio.to_thread.run_sync(review, workspace)
    workspace.agent.settings = settings
    if previous:
        previous.agent.settings = None
    catalog.active = workspace
    catalog.scope = secrets.token_urlsafe(24)
    return workspace.summary()


async def index(request):
    return FileResponse(WEB / "index.html", headers={
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
    })


async def asset(request):
    name = request.path_params["name"]
    return FileResponse(WEB / name, headers={"Cache-Control": "no-store"}) if name in ("console.css", "console.js") else Response(status_code=404)


async def dashboard(request):
    catalog = request.app.state.catalog
    workspace = catalog.active
    result = {"token": CSRF, "scope": catalog.scope, "active_case": workspace.summary() if workspace else None,
              "cases": [item.summary() for item in catalog.items.values()],
              "intake": queue_entries(catalog), "live_intake": "live" in catalog.items}
    if not workspace:
        return JSONResponse(result, headers={"Cache-Control": "no-store"})
    calls = {"environment": "get_environment_mode", "findings": "get_investigation_findings",
             "plans": "compare_response_plans", "options": "list_response_options", "outcomes": "observe_response_outcomes",
             "approvals": "list_approvals", "audit": "get_audit_log", "audit_integrity": "verify_audit_log"}
    for field, tool in calls.items():
        try:
            result[field] = await call_mcp(workspace, tool, {"limit": 20} if field == "audit" else None)
        except ResponseError as exc:
            result[field] = {"error": str(exc)}
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


async def activity(request):
    catalog = request.app.state.catalog
    workspace, scope = catalog.active, catalog.scope
    if not workspace:
        return JSONResponse({"actions": []}, headers={"Cache-Control": "no-store"})
    try:
        audit = await call_mcp(workspace, "get_audit_log", {"limit": 200})
        return JSONResponse({"scope": scope, "actions": response_activity(audit["result"])}, headers={"Cache-Control": "no-store"})
    except ResponseError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


def operator_file():
    return Path(os.environ.get("BRA_OPERATOR_FILE", "operators.local.json"))


async def agent_status(request):
    catalog = request.app.state.catalog
    workspace = catalog.active
    snapshot = workspace.agent.snapshot() if workspace else {"configured": False, "model": None, "run": None, "history": []}
    return JSONResponse({**snapshot, "scope": catalog.scope, "operators_ready": operator_file().exists()},
                        headers={"Cache-Control": "no-store"})


async def conversation_export(request):
    workspace = request.app.state.catalog.active
    if not workspace or request.query_params.get("scope") != request.app.state.catalog.scope:
        return JSONResponse({"error": "Open the incident and refresh before exporting."}, status_code=409)
    return JSONResponse({"case": workspace.summary(), "turns": workspace.agent.conversation.history(include_events=True)},
                        headers={"Cache-Control": "no-store",
                                 "Content-Disposition": 'attachment; filename="bounded-response-conversation.json"'})


async def queue(request):
    try:
        workspace = request.app.state.catalog.active
        return JSONResponse(await call_mcp(workspace, "list_approvals") if workspace else {"result": []}, headers={"Cache-Control": "no-store"})
    except ResponseError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


async def action(request):
    origin = request.headers.get("origin")
    if (not secrets.compare_digest(request.headers.get("x-operator-token", ""), CSRF)
            or (origin and origin != str(request.base_url).rstrip("/"))):
        return JSONResponse({"error": "Refresh the local console and retry."}, status_code=403)
    try:
        body = await request.json()
        operation = request.path_params["operation"]
        catalog = request.app.state.catalog
        async with catalog.lock:
            return await scoped_action(request, catalog, operation, body)
    except (ResponseError, KeyError, TypeError, ValueError, OSError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


async def scoped_action(request, catalog, operation, body):
    if operation == "select-case":
        if request.headers.get("x-case-scope", "") != (catalog.scope or ""):
            raise ResponseError("The active incident changed. Refresh before continuing.")
        return JSONResponse(await select_case(catalog, body["case"]))
    if operation == "import-case":
        return JSONResponse({"case": catalog.import_case(body["profile"], body["incident"])}, status_code=201)
    if operation == "scan-intake":
        workspace = catalog.items.get("live")
        if not workspace:
            raise ResponseError("Connect the live lab to read Suricata alerts.")
        await workspace.connect()
        findings = await call_mcp(workspace, "get_investigation_findings")
        return JSONResponse(await anyio.to_thread.run_sync(ingest_suricata, workspace, findings.get("lab_alerts", [])))
    workspace = catalog.active
    if not workspace or request.headers.get("x-case-scope", "") != catalog.scope:
        raise ResponseError("Open an incident and refresh before continuing.")
    agent = workspace.agent
    if operation == "ai-configure":
        agent.configure(body["model"], body["key"])
        return JSONResponse({"configured": True, "model": agent.settings.model})
    if operation == "ai-disconnect":
        if agent.task is not None and not agent.task.done():
            raise ResponseError("Clear the key after the current run finishes.")
        agent.settings = None
        return JSONResponse({"configured": False})
    if operation == "ai-run":
        agent.start(body["goal"], body["mode"], workspace.summary())
        return JSONResponse({"status": "running"}, status_code=202)
    if operation == "provision-operators":
        credentials = operator_file()
        if credentials.exists():
            raise ResponseError("Operator identities have already been provisioned.")
        await anyio.to_thread.run_sync(provision, credentials,
                                       {"soc-watch": body["soc"], "ot-watch": body["ot"]})
        return JSONResponse({"operators_ready": True})
    tools = {"request": ("request_operator_approval", ("action", "target", "rationale")),
             "execute": ("execute_approved_action", ("approval_id",)),
             "verify": ("verify_system_state", ("execution_id",)),
             "rollback": ("rollback_action", ("execution_id",))}
    if operation in tools:
        tool, fields = tools[operation]
        return JSONResponse(await call_mcp(workspace, tool, {key: body[key] for key in fields}))
    if operation in ("approve", "deny", "authorize-rollback"):
        service = workspace.service
        identity = body["identity"]
        credentials = operator_file()

        def decide():
            role = authenticate(credentials, identity, body["passphrase"])
            if operation == "authorize-rollback":
                service.authorize_rollback(body["execution_id"], role, identity, body["note"])
                return {"status": "rollback_authorized"}
            return service.decide(body["approval_id"], operation, role, identity, body.get("note"))

        return JSONResponse(await anyio.to_thread.run_sync(decide))
    return JSONResponse({"error": "Unknown operation."}, status_code=404)


app = Starlette(routes=[Route("/", index), Route("/assets/{name}", asset),
                        Route("/api/dashboard", dashboard), Route("/api/ai", agent_status),
                        Route("/api/conversation", conversation_export), Route("/api/activity", activity), Route("/api/approvals", queue), Route("/api/{operation}", action, methods=["POST"])],
                lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    uvicorn.run(app, host="127.0.0.1", port=parser.parse_args().port, proxy_headers=False)
