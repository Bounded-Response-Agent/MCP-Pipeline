"""
MCP client + agent loop for the Bounded Response Agent.

This is the 'host' for the assignment: it starts server.py over stdio, discovers its
tools via MCP, hands their schemas to an OpenAI-compatible chat API, and executes
whichever tool calls the model requests -- looping until the model gives a final text
answer. Requires LLM_API_KEY in the environment.

Usage:
    export LLM_API_KEY=...
    python client.py "Which source IP has been hitting db01 with denied connections, and can you quarantine it?"
"""
import asyncio
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE_URL = os.environ.get("LLM_BASE_URL", "https://128.171.10.80:9443/v1")
MODEL_CANDIDATES = [
    os.environ.get("LLM_MODEL", "gpt-oss-120b"),
    "llama-4-scout",
    "muse-glimmer",
]
SERVER_CMD = sys.executable
SERVER_ARGS = [str(Path(__file__).with_name("server.py"))]


async def create_completion(messages, tools, model):
    """Send one OpenAI-compatible chat completion request."""
    payload = json.dumps(
        {
            "model": model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "max_tokens": 1024,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{BASE_URL}/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {os.environ['LLM_API_KEY']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    def send_request():
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM gateway returned HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Could not reach LLM gateway: {exc.reason}") from exc

    return await asyncio.to_thread(send_request)


async def create_completion_with_retry(messages, tools):
    """Retry transient gateway/upstream errors without crashing."""
    last_error = None
    for model in MODEL_CANDIDATES:
        for attempt in range(4):
            try:
                return await create_completion(messages, tools, model)
            except RuntimeError as exc:
                last_error = exc
                message = str(exc).lower()
                is_transient = any(
                    marker in message
                    for marker in ("http 500", "http 503", "temporarily unavailable")
                )
                if not is_transient:
                    raise
                wait_seconds = min(8, 2 ** attempt)
                print(f"[client] model '{model}' temporarily unavailable; retrying in {wait_seconds}s (attempt {attempt + 1}/4)")
                await asyncio.sleep(wait_seconds)
        print(f"[client] model '{model}' failed after retries; trying next candidate")
    raise RuntimeError(f"All configured models failed. Last error: {last_error}")


def mcp_tools_to_openai(tools) -> list[dict]:
    """Convert MCP tool definitions into OpenAI function tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": tool.input_schema,
            },
        }
        for tool in tools
    ]


async def run_agent(goal: str) -> None:
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        raise RuntimeError("LLM_API_KEY is not set in the environment.")
    params = StdioServerParameters(command=SERVER_CMD, args=SERVER_ARGS)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            discovered = await session.list_tools()
            tools = mcp_tools_to_openai(discovered.tools)
            print(f"[client] discovered tools: {[t.name for t in discovered.tools]}\n")

            messages = [{"role": "user", "content": goal}]

            for _ in range(8):  # safety cap on agent loop length
                response = await create_completion_with_retry(messages, tools)
                message = response["choices"][0]["message"]
                if message.get("content") and message["content"].strip():
                    print(f"[model] {message['content'].strip()}\n")

                if not message.get("tool_calls"):
                    print("[client] final answer above.")
                    return

                messages.append(message)

                for call in message["tool_calls"]:
                    arguments = json.loads(call["function"]["arguments"])
                    name = call["function"]["name"]
                    print(f"[tool_call] {name}({json.dumps(arguments)})")
                    result = await session.call_tool(name, arguments)
                    text = " ".join(c.text for c in result.content if hasattr(c, "text"))
                    status = "ERROR" if result.is_error else "ok"
                    print(f"[tool_result:{status}] {text}\n")
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": json.dumps(
                                {"result": text, "is_error": result.is_error}
                            ),
                        }
                    )

            print("[client] stopped after max turns without a final answer.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py \"<goal for the agent>\"")
        sys.exit(1)
    asyncio.run(run_agent(sys.argv[1]))
