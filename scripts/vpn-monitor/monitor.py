#!/usr/bin/env python3
"""Read-only VPN observability module. Python stdlib, systemd, curl, iproute2."""
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = 1
MODULE = "vpn.amneziawg"


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, ValueError):
        return default


def write_json(path, value):
    path = Path(path)
    temp = path.with_suffix(".tmp")
    with temp.open("w") as stream:
        os.chmod(temp, 0o640)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def run(args, timeout=10):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          check=False, env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})


def curl_check(url, expected_code=200):
    started = time.monotonic()
    try:
        result = run(["curl", "--noproxy", "*", "-4", "--silent", "--show-error",
                      "--connect-timeout", "4", "--max-time", "9", "--max-filesize", "65536",
                      "--proto", "=https", "--write-out", "\n%{http_code}", url], timeout=11)
        body, _, code = result.stdout.rpartition("\n")
        ok = result.returncode == 0 and code == str(expected_code)
        return {"ok": ok, "http_status": int(code) if code.isdigit() else None,
                "latency_ms": round((time.monotonic() - started) * 1000),
                "error": None if ok else "https_request_failed"}, body
    except (subprocess.TimeoutExpired, OSError):
        return {"ok": False, "error": "https_timeout_or_unavailable"}, ""


def dns_check(server):
    started = time.monotonic()
    transaction = os.urandom(2)
    question = b"\x07example\x03com\x00\x00\x01\x00\x01"
    packet = transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.connect((server, 53))
            client.send(packet)
            reply = client.recv(4096)
        flags, _, answers = struct.unpack("!HHH", reply[2:8])
        ok = reply[:2] == transaction and bool(flags & 0x8000) and flags & 15 == 0 and answers > 0
        return {"ok": ok, "latency_ms": round((time.monotonic() - started) * 1000),
                "error": None if ok else "dns_invalid_response"}
    except (OSError, struct.error):
        return {"ok": False, "error": "dns_timeout_or_unavailable"}


def network_check(config):
    # This command runs as an unprivileged user in an existing AWG network namespace.
    started = int(time.time())
    dns = dns_check(config["dns_server"])
    trace, body = curl_check("https://www.cloudflare.com/cdn-cgi/trace")
    trace_fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
    observed = trace_fields.get("ip")
    try:
        observed = str(ipaddress.ip_address(observed))
    except (ValueError, TypeError):
        observed = None
    trace["exit_ip"] = observed
    trace["exit_matches"] = observed == config["expected_exit_ip"] if observed else None
    alternate, _ = curl_check("https://www.gstatic.com/generate_204", 204)
    if trace["ok"] and trace["exit_matches"] and dns["ok"] and alternate["ok"]:
        observation, reason = "up", "all_checks_passed"
    elif trace["ok"] and observed and not trace["exit_matches"]:
        observation, reason = "down", "unexpected_exit_ip"
    elif not trace["ok"] and not alternate["ok"]:
        observation, reason = "down", "both_https_targets_unreachable"
    else:
        observation, reason = "degraded", "partial_check_failure"
    result = {"started_at": started, "checked_at": int(time.time()),
              "observation": observation, "reason": reason,
              "checks": {"dns": dns, "https_trace": trace, "https_alternate": alternate}}
    write_json(config["netcheck_result"], result)
    return result


def gateway_snapshot(config):
    files = config["gateway_guard"]
    result = {"mode": Path(files["mode_file"]).read_text().strip()}
    for key in ("config_file", "resolver_file"):
        result[key] = hashlib.sha256(Path(files[key]).read_bytes()).hexdigest()
    for key, command in (("routes", ["ip", "-4", "route", "show", "table", "main"]),
                         ("rules", ["ip", "-4", "rule", "show"])):
        response = run(command)
        if response.returncode:
            raise RuntimeError("gateway_guard_unavailable")
        result[key] = response.stdout
    return result


def open_database(config):
    connection = sqlite3.connect(config["database"], timeout=5)
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS samples (id INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_at INTEGER NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, payload TEXT NOT NULL);
    """)
    os.chmod(config["database"], 0o640)
    return connection


def transition(previous, sample, threshold):
    """Debounce outages; recover immediately after a completely successful probe."""
    previous = previous or {"status": "unknown", "consecutive_failures": 0}
    failures = 0 if sample["observation"] == "up" else previous["consecutive_failures"] + 1
    status = "up" if not failures else (sample["observation"] if failures >= threshold else previous["status"])
    state = {"status": status, "consecutive_failures": failures,
             "checked_at": sample["checked_at"], "last_observation": sample["observation"],
             "reason": sample["reason"], "gateway_mode": sample.get("gateway_mode", "unknown")}
    event = None
    if status != previous["status"]:
        event = "recovered" if status == "up" and previous["status"] in ("down", "degraded") else "state_changed"
    return state, event


def store_sample(config, sample):
    with open_database(config) as db:
        row = db.execute("SELECT payload FROM state WHERE key='health'").fetchone()
        previous = json.loads(row[0]) if row else None
        state, event = transition(previous, sample, config["failure_threshold"])
        db.execute("INSERT INTO samples(checked_at,payload) VALUES(?,?)",
                   (sample["checked_at"], json.dumps(sample)))
        db.execute("INSERT OR REPLACE INTO state VALUES('health',?)", (json.dumps(state),))
        if event:
            db.execute("INSERT INTO events(created_at,kind,payload) VALUES(?,?,?)",
                       (sample["checked_at"], event, json.dumps(state)))
        cutoff = int(time.time()) - config["retention_days"] * 86400
        db.execute("DELETE FROM samples WHERE checked_at < ?", (cutoff,))
        db.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
    return state


def health_check(config):
    sample = {"checked_at": int(time.time()), "observation": "down", "reason": "collector_failed", "checks": {}}
    before = None
    try:
        before = gateway_snapshot(config)
        sample["gateway_mode"] = before["mode"]
        allowed_modes = config["gateway_guard"].get("expected_modes", [config["gateway_guard"].get("expected_mode", "direct")])
        if before["mode"] not in allowed_modes:
            sample["reason"] = "gateway_mode_changed_monitor_needs_review"
        else:
            started = int(time.time())
            child = run(["systemctl", "start", "vpn-monitor-netcheck.service"], timeout=45)
            collected = read_json(config["netcheck_result"], {})
            if child.returncode == 0 and collected.get("started_at", 0) >= started:
                sample.update(collected)
            else:
                sample["reason"] = "isolated_probe_service_failed"
            after = gateway_snapshot(config)
            if before != after:
                sample.update(observation="down", reason="gateway_guard_changed")
            sample["checks"]["gateway_unchanged"] = {"ok": before == after}
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        sample["reason"] = "collector_or_gateway_guard_failed"
    sample["checked_at"] = int(time.time())
    if sample["observation"] != "up":
        # Independent control: a failed monitor probe does not by itself prove protocol blocking.
        sample["checks"]["direct_https"], _ = curl_check("https://www.gstatic.com/generate_204", 204)
        try:
            with socket.create_connection((config["expected_exit_ip"], 22), timeout=3):
                reachable = True
        except OSError:
            reachable = False
        sample["checks"]["vps_ssh_tcp"] = {"ok": reachable}
    state = store_sample(config, sample)
    print(json.dumps({"schema_version": SCHEMA, "module_id": MODULE, "health": state}))
    return state


def version_tuple(tag):
    return tuple(int(part) for part in re.findall(r"\d+", tag))


def select_versions(entries, kind, installed):
    if kind == "tags":
        rows = [{"version": row["name"], "prerelease": False,
                 "url": "", "published_at": None} for row in entries
                if re.fullmatch(r"v?\d+(?:\.\d+)+", row.get("name", ""))]
    else:
        rows = [{"version": row["tag_name"], "prerelease": bool(row.get("prerelease")),
                 "url": row.get("html_url", ""), "published_at": row.get("published_at")}
                for row in entries if not row.get("draft") and row.get("tag_name")]
    rows.sort(key=lambda row: version_tuple(row["version"]), reverse=True)
    stable = next((row for row in rows if not row["prerelease"]), None)
    return {"latest_stable": stable, "latest_any": rows[0] if rows else None,
            "update_available": bool(installed and stable and version_tuple(stable["version"]) > version_tuple(installed))}


def github_fetch(url, cached):
    headers = {"User-Agent": "personal-vpn-monitor/1", "Accept": "application/vnd.github+json"}
    if cached.get("etag"):
        headers["If-None-Match"] = cached["etag"]
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read(2_000_001)
            if len(data) > 2_000_000:
                raise ValueError("response_too_large")
            entries = json.loads(data)
            if isinstance(entries, dict) and url.endswith("/latest") and "tag_name" in entries:
                entries = [entries]
            if not isinstance(entries, list):
                raise ValueError("unexpected_response")
            # Asset inventories and release bodies are unnecessary for version checks.
            # Keep the cache small and avoid serving arbitrary release text via our API.
            entries = [{key: row[key] for key in ("name", "tag_name", "draft", "prerelease", "html_url", "published_at")
                        if key in row} for row in entries]
            return {"etag": response.headers.get("ETag"), "entries": entries,
                    "fetched_at": int(time.time())}
    except urllib.error.HTTPError as error:
        if error.code == 304 and "entries" in cached:
            return dict(cached, fetched_at=int(time.time()))
        raise


def check_updates(config):
    cache = read_json(config["updates_cache"], {})
    old = read_json(config["updates_result"], {})
    old_components = {row["id"]: row for row in old.get("components", [])}
    components = []
    for source in config["components"]:
        row = {key: source.get(key) for key in ("id", "repo", "installed", "installed_as_of", "watch_only")}
        repo, kind = source["repo"], source["kind"]
        url = "https://api.github.com/repos/" + repo + "/" + kind + "?per_page=5"
        row["source_url"] = "https://github.com/" + repo + "/" + kind
        try:
            fresh = github_fetch(url, cache.get(repo, {}))
            cache[repo] = fresh
            row.update(select_versions(fresh["entries"], kind, source.get("installed")))
            if kind == "releases" and row["latest_stable"] is None:
                # A busy project can publish many prereleases between stable releases.
                stable = github_fetch("https://api.github.com/repos/" + repo + "/releases/latest", cache.get(repo + "/stable", {}))
                cache[repo + "/stable"] = stable
                row.update(select_versions(fresh["entries"] + stable["entries"], kind, source.get("installed")))
            if kind == "tags":
                for key in ("latest_any", "latest_stable"):
                    if row[key]:
                        row[key]["url"] = "https://github.com/" + repo + "/tree/" + urllib.parse.quote(row[key]["version"], safe="")
            row.update(fetch_status="ok", last_success_at=fresh["fetched_at"])
        except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
            previous = old_components.get(source["id"], {})
            for key in ("latest_stable", "latest_any", "update_available", "last_success_at"):
                row[key] = previous.get(key)
            row["fetch_status"] = "error"
            row["error_kind"] = "http_" + str(error.code) if isinstance(error, urllib.error.HTTPError) else type(error).__name__
        components.append(row)
    result = {"schema_version": SCHEMA, "module_id": MODULE, "checked_at": int(time.time()),
              "status": "ok" if all(row["fetch_status"] == "ok" for row in components) else "partial_error",
              "automatic_installation": False, "components": components}
    write_json(config["updates_cache"], cache)
    write_json(config["updates_result"], result)
    print(json.dumps(result))
    return result


def read_database(config, query, parameters=()):
    # Separate API user has read access only, including to SQLite's parent directory.
    uri = Path(config["database"]).resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=3) as db:
        return db.execute(query, parameters).fetchall()


def status(config):
    try:
        rows = read_database(config, "SELECT payload FROM state WHERE key='health'")
        health = json.loads(rows[0][0]) if rows else {"status": "unknown"}
    except sqlite3.Error:
        health = {"status": "unknown"}
    age = max(0, int(time.time()) - health.get("checked_at", 0))
    health["age_seconds"] = age
    health["stale"] = age > config["stale_after_seconds"]
    if health["stale"]:
        health["last_known_status"] = health["status"]
        health["status"] = "stale"
    updates = read_json(config["updates_result"], {})
    return {"schema_version": SCHEMA, "module_id": MODULE, "generated_at": int(time.time()),
            "health": health, "updates": {"status": updates.get("status", "unknown"),
            "checked_at": updates.get("checked_at"),
            "stale": int(time.time()) - updates.get("checked_at", 0) > 8 * 86400},
            "gateway": read_json(config.get("control_status", "/var/lib/home-gateway-control/status.json"), {}),
            "control_enabled": False}


def serve(config):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "VpnMonitor/1"

        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.headers.get("Host") not in ("127.0.0.1:18765", "localhost:18765"):
                self.send_error(403)
                return
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            try:
                limit = min(1000, max(1, int(query.get("limit", ["100"])[0])))
                cursor = max(0, int(query.get("after_id", ["0"])[0]))
            except ValueError:
                self.send_error(400)
                return
            try:
                content_type = "application/json; charset=utf-8"
                if parsed.path == "/v1/status":
                    data = status(config)
                elif parsed.path == "/v1/manifest":
                    data = read_json(Path(__file__).with_name("manifest.json"), {})
                elif parsed.path == "/v1/updates":
                    data = read_json(config["updates_result"], {"status": "unknown"})
                elif parsed.path in ("/v1/history", "/v1/events"):
                    if parsed.path.endswith("history"):
                        rows = read_database(config, "SELECT id,payload FROM samples ORDER BY id DESC LIMIT ?", (limit,))
                        items = [dict(json.loads(payload), id=identifier) for identifier, payload in rows]
                    else:
                        rows = read_database(config, "SELECT id,created_at,kind,payload FROM events WHERE id>? ORDER BY id LIMIT ?", (cursor, limit))
                        items = [{"id": row[0], "created_at": row[1], "kind": row[2], "health": json.loads(row[3])} for row in rows]
                    data = {"schema_version": SCHEMA, "module_id": MODULE, "items": items}
                    if parsed.path.endswith("events"):
                        data["next_after_id"] = items[-1]["id"] if items else cursor
                elif parsed.path == "/metrics":
                    current = status(config)["health"]
                    data = ("# TYPE vpn_probe_up gauge\nvpn_probe_up " + str(int(current["status"] == "up")) +
                            "\n# TYPE vpn_probe_stale gauge\nvpn_probe_stale " + str(int(current["stale"])) +
                            "\nvpn_probe_last_check_seconds " + str(current.get("checked_at", 0)) + "\n")
                    content_type = "text/plain; version=0.0.4"
                else:
                    self.send_error(404)
                    return
                body = (data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)).encode()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except (sqlite3.Error, OSError, ValueError):
                self.send_error(503, "Monitor data unavailable")
    class Server(http.server.HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            return connection, address
    Server(("127.0.0.1", 18765), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("health", "netcheck", "updates", "serve", "status"))
    parser.add_argument("--config", default="/etc/vpn-monitor/config.json")
    args = parser.parse_args()
    config = read_json(args.config)
    if not config:
        parser.error("Configuration missing or invalid")
    if args.command == "status":
        print(json.dumps(status(config)))
    else:
        {"health": health_check, "netcheck": network_check,
         "updates": check_updates, "serve": serve}[args.command](config)


if __name__ == "__main__":
    main()
