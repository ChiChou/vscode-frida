#!/usr/bin/env python3

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rpc import AppAgent, ProcessAgent


def read_config(workspace_root: str) -> dict:
    config_path = Path(workspace_root) / ".vscode" / "frida.json"
    with open(config_path, "r") as f:
        config = json.load(f)

    if "device" not in config:
        raise ValueError('"device" is required in frida.json')

    targets = [k for k in ("app", "pid", "process") if k in config]
    if len(targets) == 0:
        raise ValueError('frida.json must specify one of "app", "pid", or "process"')
    if len(targets) > 1:
        raise ValueError(
            f'frida.json must specify only one of "app", "pid", or "process", got: {", ".join(targets)}'
        )

    return config


def create_agent(config: dict):
    from backend import core, rpc

    device = core.get_device(config["device"])

    if "app" in config:
        agent = rpc.AppAgent(device, config["app"])
    elif "pid" in config:
        agent = rpc.ProcessAgent(device, config["pid"])
    else:
        name = config["process"]
        processes = device.enumerate_processes()
        matches = [p for p in processes if p.name == name]
        if len(matches) == 0:
            raise RuntimeError(f'No process found with name "{name}"')
        if len(matches) > 1:
            pids = ", ".join(str(p.pid) for p in matches)
            raise RuntimeError(
                f'Multiple processes found with name "{name}" '
                f'(pids: {pids}). Use "pid" instead.'
            )
        agent = rpc.ProcessAgent(device, matches[0].pid)

    agent.load()
    runtime = agent.invoke("runtime")
    return agent, runtime


def handle_request(agent: AppAgent | ProcessAgent, request: dict) -> dict:
    req_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    try:
        if method == "classes":
            result = agent.invoke("classes")
        elif method == "modules":
            raw = agent.invoke("modules")
            result = [m["name"] for m in raw]
        elif method == "exports":
            module_name = params["module"]
            raw = agent.invoke("exports", module_name)
            result = [e["name"] for e in (raw or [])]
        elif method == "methods":
            class_name = params["className"]
            raw = agent.invoke("own_methods_of", class_name)
            result = [m["display"] if isinstance(m, dict) else m for m in (raw or [])]
        elif method == "classMembers":
            class_name = params["className"]
            raw = agent.invoke("class_members", class_name)
            if raw:
                methods = [m["name"] for m in raw.get("methods", [])]
                fields = [f["name"] for f in raw.get("fields", [])]
                result = {"methods": methods, "fields": fields}
            else:
                result = {"methods": [], "fields": []}
        else:
            return {"id": req_id, "error": f"Unknown method: {method}"}

        return {"id": req_id, "result": result}
    except Exception as e:
        return {"id": req_id, "error": str(e)}


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: lsp.py <workspace_root>\n")
        sys.exit(1)

    workspace_root = sys.argv[1]

    try:
        config = read_config(workspace_root)
    except (json.JSONDecodeError, ValueError, FileNotFoundError) as e:
        sys.stderr.write(f"frida.json error: {e}\n")
        sys.exit(1)

    try:
        agent, runtime = create_agent(config)
    except Exception as e:
        sys.stderr.write(f"Frida session error: {e}\n")
        sys.exit(2)

    sys.stdout.write(json.dumps({"ready": True, "runtime": runtime}) + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            resp = json.dumps({"id": None, "error": f"Invalid JSON: {e}"})
            sys.stdout.write(resp + "\n")
            sys.stdout.flush()
            continue

        response = handle_request(agent, request)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
