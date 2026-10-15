#!/usr/bin/env python3
"""SSH API consumer with a durable notification outbox; no VPN credentials."""
import argparse
import fcntl
import json
from pathlib import Path
import shlex
import subprocess
import time


def health_notices(state, data):
    notices = []
    if data is None:
        state["unreachable_count"] = state.get("unreachable_count", 0) + 1
        state.setdefault("unreachable_since", int(time.time()))
        if state["unreachable_count"] == 2:
            notices.append({"id": "observer-unreachable-" + str(state["unreachable_since"]),
                            "kind": "monitor_unreachable", "message": "SSH/API unavailable; AWG state is unknown, not proven down"})
        return notices
    if state.get("unreachable_count", 0) >= 2:
        notices.append({"id": "observer-recovered-" + str(state["unreachable_since"]), "kind": "monitor_reachable"})
    state["unreachable_count"] = 0
    state.pop("unreachable_since", None)
    current = data["status"]["health"]
    cursor = state.get("cursor", 0)
    for event in data["events"]["items"]:
        if event["id"] <= cursor:
            continue
        if event["health"]["status"] in ("down", "degraded") or event["kind"] == "recovered":
            notices.append(dict(event, id="health-event-" + str(event["id"])))
    state["cursor"] = data["events"]["next_after_id"]
    previous = state.get("last_status")
    if current["status"] == "stale" and previous != "stale":
        notices.append({"id": "stale-" + str(current.get("checked_at", 0)), "kind": "monitor_stale", "health": current})
    elif previous == "stale" and current["status"] == "up":
        notices.append({"id": "fresh-" + str(current.get("checked_at", 0)), "kind": "monitor_fresh", "health": current})
    # Also detect the current state if old events expired or the consumer is new.
    if current["status"] in ("down", "degraded") and previous != current["status"] and not notices:
        notices.append({"id": "current-" + str(current["checked_at"]), "kind": "current_failure", "health": current})
    state["last_status"] = current["status"]
    transition = data["status"].get("gateway", {}).get("last_transition", {})
    if transition.get("kind") == "automatic_rollback" and transition.get("at") != state.get("last_rollback_at"):
        notices.append({"id": "rollback-" + str(transition["at"]), "kind": "automatic_rollback", "transition": transition})
        state["last_rollback_at"] = transition["at"]
    return notices


def update_notices(state, data):
    if data is None:
        if not state.get("unreachable"):
            state["unreachable"] = True
            return [{"id": "updates-unreachable-" + str(int(time.time())), "kind": "updates_unreachable"}]
        return []
    state["unreachable"] = False
    notices = []
    previous = state.get("versions", {})
    versions = {}
    for component in data["updates"].get("components", []):
        stable = (component.get("latest_stable") or {}).get("version")
        latest = (component.get("latest_any") or {}).get("version")
        value = {"stable": stable, "latest": latest, "fetch_status": component["fetch_status"]}
        component_id = component["id"]
        versions[component_id] = value
        old = previous.get(component_id)
        if ((old is not None and old != value) or
                (old is None and (component.get("update_available") or component["fetch_status"] != "ok"))):
            notices.append({"id": component_id + "-" + str(data["updates"]["checked_at"]),
                            "kind": "upstream_changed", "component": component})
    state["versions"] = versions
    return notices


def retrieve(args, cursor):
    paths = {"status": "/v1/status", "events": "/v1/events?limit=1000&after_id=" + str(cursor)} if args.kind == "health" else {"updates": "/v1/updates"}
    script = """import json,urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
paths=PATHS
output={}
for key,path in paths.items():
    with opener.open('http://127.0.0.1:18765'+path,timeout=5) as response:
        raw=response.read(1000001)
        if len(raw)>1000000: raise ValueError('response_too_large')
        output[key]=json.loads(raw)
print(json.dumps(output))
""".replace("PATHS", repr(paths))
    command = ["ssh", "-F", args.ssh_config, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
               args.target, "python3 -c " + shlex.quote(script)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=25, check=True)
        data = json.loads(result.stdout)
        for value in data.values():
            if value.get("module_id") != "vpn.amneziawg" or value.get("schema_version") != 1:
                raise ValueError("unsupported_module_schema")
        return data
    except (subprocess.SubprocessError, OSError, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("poll", "ack"))
    parser.add_argument("--kind", choices=("health", "updates"), required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--ssh-config")
    parser.add_argument("--target")
    parser.add_argument("--ids", nargs="*", default=[])
    args = parser.parse_args()
    state_path = Path(args.state)
    if args.command == "poll" and not (args.ssh_config and args.target):
        parser.error("poll requires --ssh-config and --target")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with state_path.with_suffix(".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(state_path.read_text()) if state_path.exists() else {"schema_version": 1}
        consumer = state.setdefault(args.kind, {"pending": []})
        data = None
        if args.command == "ack":
            consumer["pending"] = [row for row in consumer["pending"] if row["id"] not in args.ids]
        else:
            data = retrieve(args, consumer.get("cursor", 0))
            notices = (health_notices if args.kind == "health" else update_notices)(consumer, data)
            known = {row["id"] for row in consumer["pending"]}
            consumer["pending"].extend(row for row in notices if row["id"] not in known)
            consumer["last_polled_at"] = int(time.time())
        temp = state_path.with_suffix(".tmp")
        temp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")
        temp.replace(state_path)
        print(json.dumps({"kind": args.kind, "pending_notices": consumer["pending"], "snapshot": data}, ensure_ascii=False))


if __name__ == "__main__":
    main()
