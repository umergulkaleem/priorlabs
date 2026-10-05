"""Interactive terminal client for the IDS MCP server."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _result_json(result: Any) -> Any:
    if getattr(result, "structuredContent", None):
        return result.structuredContent
    for item in getattr(result, "content", []):
        text = getattr(item, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    return {"error": "empty_mcp_response"}


async def run_cli() -> None:
    parser = argparse.ArgumentParser(description="Call the IDS agent through MCP from a terminal.")
    parser.add_argument("--python", default=r"C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe")
    parser.add_argument("--cwd", default=str(Path(__file__).resolve().parent))
    args = parser.parse_args()
    server = StdioServerParameters(
        command=args.python,
        args=["-m", "src.mcp_server"],
        cwd=args.cwd,
    )

    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("Connected to IDS MCP server.")
            print("Type 'help' for commands or 'quit' to exit.")
            print("Available tools:", ", ".join(tool.name for tool in tools.tools))
            while True:
                try:
                    command = input("ids-mcp> ").strip()
                except EOFError:
                    break
                if not command:
                    continue
                if command in {"quit", "exit"}:
                    break
                if command == "help":
                    print("load <path> [rows] | train [label] [rows] | compare | reliability")
                    print("alerts | disagreement | uncertain | false-positives | false-negatives | errors | ask <question>")
                    continue
                try:
                    name, *parts = command.split(" ", 1)
                    if name == "load":
                        path_and_rows = parts[0].split()
                        arguments = {"path": path_and_rows[0], "max_rows": int(path_and_rows[1]) if len(path_and_rows) > 1 else 1000}
                        tool_name = "load_intrusion_dataset"
                    elif name == "train":
                        label_and_rows = parts[0].split() if parts else []
                        arguments = {
                            "label_column": label_and_rows[0] if label_and_rows else "is_attack",
                            "model_name": "tabpfn",
                            "max_rows": int(label_and_rows[1]) if len(label_and_rows) > 1 else 1000,
                        }
                        tool_name = "train_ids_model"
                    elif name == "compare":
                        tool_name, arguments = "evaluate_ids_models", {}
                    elif name == "reliability":
                        tool_name, arguments = "get_reliability_report", {}
                    elif name == "alerts":
                        tool_name, arguments = "get_high_risk_alerts", {"limit": 10}
                    elif name == "disagreement":
                        tool_name, arguments = "get_model_disagreement", {"limit": 10}
                    elif name == "uncertain":
                        tool_name, arguments = "get_uncertain_predictions", {"limit": 10}
                    elif name == "false-positives":
                        tool_name, arguments = "get_false_positives", {"limit": 10}
                    elif name == "false-negatives":
                        tool_name, arguments = "get_false_negatives", {"limit": 10}
                    elif name == "errors":
                        tool_name, arguments = "get_high_confidence_errors", {"limit": 10}
                    elif name == "ask":
                        tool_name, arguments = "investigate_ids", {"question": parts[0] if parts else ""}
                    else:
                        print("Unknown command. Type 'help'.")
                        continue
                    result = await session.call_tool(tool_name, arguments)
                    print(json.dumps(_result_json(result), indent=2, default=str))
                except (ValueError, IndexError) as error:
                    print(f"Invalid command: {error}")


if __name__ == "__main__":
    asyncio.run(run_cli())
