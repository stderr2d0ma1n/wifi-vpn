# VPN observability module

Read-only monitoring for an existing isolated AmneziaWG probe on a Linux gateway.
The module is independent of Codex and can become one backend module in a personal
admin application. It neither switches household traffic nor installs updates.

## Checks and schedules

- Every five minutes: a real DNS request, TLS-verified HTTPS requests to two
  independent sites, and verification of the VPN's expected public exit IP.
- Before and after each probe: check the household gateway mode, configuration
  hash, resolver hash, main routes and policy rules. The initial expected mode is
  `direct`; the prepared household gateway explicitly allows `direct` and `rules`
  through `gateway_guard.expected_modes`.
- After a failure: direct HTTPS and VPS SSH-port reachability as diagnostic
  controls. These controls do not identify censorship conclusively.
- Three consecutive abnormal observations confirm `down` or `degraded`.
  One completely successful observation clears an incident. Isolated failures
  remain visible in history. No new sample for 15 minutes means `stale`.
- History and transition events are retained for 30 days in SQLite; consumers
  keep independent event cursors. Database pages are reused after retention
  cleanup; this workload does not need periodic full vacuum operations.
- Official upstream tags/releases are checked on Mondays at 09:40 Moscow time,
  with up to two minutes of random delay and a persistent catch-up timer.
  Tags are used for amneziawg-go because that repository has no Releases feed.
  Stable and prerelease versions are shown separately. Failed fetches retain
  previous successful results and explicitly mark their age/error.

Health is end-to-end for the Orange Pi test peer and its home ISP path, not a
test of an iPhone's mobile network. A successful web request proves useful
traffic crossed the tunnel; there is no idle-peer handshake alarm. This avoids
false alarms when a phone is asleep. No periodic throughput test is performed.

Installed versions in the upstream checker are a dated deployment inventory.
They must be refreshed when software is changed; this module never assumes a
tag comparison alone proves compatibility or security. Weekly review should
also read release notes and official protocol documentation. A new tag or
prerelease is a candidate for review, not an instruction to upgrade.

## Installation

Dependencies: Python 3.9+, curl, iproute2, systemd with NetworkNamespacePath
support, CA certificates, and the existing home-gateway AWG probe units from
`../home-gateway/`. Tested on systemd 257 and Python 3.13. Uses only the Python
standard library; no Python package installation is required.

1. Inspect the current deployment and confirm that the main mode is `direct`.
2. Copy `config.example.json` outside the portable source tree. Fill in the
   public exit address and dated installed versions. Do not add VPN keys,
   subscription links or account credentials.
3. Copy this directory and the public configuration onto the gateway. As root:

   ```sh
   bash install.sh /path/to/module /path/to/config.json
   ```

The installer refuses an existing configuration instead of overwriting it. For
an intentional module upgrade, preserve the deployed configuration and compare
source hashes before replacing code or units. Do not rerun the first-install
script over an existing deployment.

The health coordinator starts only the fixed isolated network-check service.
Its dependency starts the existing AWG probe after boot. The AWG profile,
interface and network namespace are reused without modifying the main gateway.
The prepared deployment adapts the allowed-mode list alongside the gateway
safety module. This does not authorize activation. The optional `gateway`
status includes local watchdog state and the last automatic rollback event;
the API remains read-only.

The collector and updater run as `vpn-monitor`. The API runs as a separate
`vpn-monitor-api` user with read access only. The root coordinator reads the
root-only gateway mode and config, records results, and starts the fixed probe
service; its Linux capability set is empty and its filesystem is read-only
except for its own state directory. No process exposes VPN keys through the API.

Inspect operation:

```sh
systemctl list-timers 'vpn-monitor-*'
systemctl status vpn-monitor-api.service
curl --noproxy '*' http://127.0.0.1:18765/v1/status
curl --noproxy '*' http://127.0.0.1:18765/v1/updates
journalctl -u vpn-monitor-health.service -u vpn-monitor-netcheck.service -n 30
```

Stop monitoring without changing traffic routing:

```sh
systemctl disable --now vpn-monitor-health.timer vpn-monitor-updates.timer vpn-monitor-api.service
```

These commands leave the existing isolated AWG probe untouched. They never
stop the VPS service or the iPhone peer. The module does not provide automatic
server failover, automatic public-IP changes, or automatic direct fallback.

## Interface for a future admin application

Module ID: `vpn.amneziawg`; schema/API version: `1` / `v1`.
HTTP listens only on `127.0.0.1:18765`. There is no public port, CORS, or write
API. Only `Host: localhost:18765` or `127.0.0.1:18765` is accepted. Requests with
POST/PUT/DELETE are rejected by the HTTP server. Do not expose this HTTP server
directly to the LAN or Internet. A future backend can use SSH forwarding or a
local authenticated reverse proxy and embed its own UI and access controls.

| GET endpoint | Contract |
| --- | --- |
| `/v1/manifest` | Module capabilities, API version, nominal intervals |
| `/v1/status` | `schema_version`, `module_id`, `generated_at`, `health`, update freshness, `control_enabled: false` |
| `/v1/history?limit=100` | `items`: newest-first probe results, checks and latencies, bounded to 1,000 entries |
| `/v1/events?after_id=0&limit=100` | Oldest-first transitions, monotonic `id`, `next_after_id` cursor |
| `/v1/updates` | Latest official release/tag candidates, source URLs, fetch state and dated installed inventory |
| `/metrics` | Prometheus gauges: probe up, stale, and last check timestamp |

Timestamps are Unix seconds in UTC. `health.status` is one of `unknown`, `up`,
`down`, `degraded`, `stale`. `last_observation` shows the current result even
before the failure threshold is reached. A `stale` status also includes
`last_known_status`; it must never be shown as currently healthy. Transition
events use `state_changed` and `recovered`. A first successful baseline is a
`state_changed` event, not a recovery notification.

Consumers must inspect both current status and events: events expire after 30
days. Consumers can maintain a high-water-mark cursor and deduplicate failures
by event ID. If the module database is deliberately recreated, reset consumer
cursors. The updater results are separate snapshots rather than event rows.

Read data through an SSH tunnel on the admin host:

```sh
ssh -N -L 127.0.0.1:18765:127.0.0.1:18765 YOUR_GATEWAY_ALIAS
```

The API contains operational details such as public exit IP and timing, but no
VPN credentials or user traffic history. DNS checks query only `example.com`;
the module does not record household DNS or connection logs.

## Notifications and failure limits

The Pi timers run without a Mac or Codex. Chat notifications are a separate
scheduled consumer. Local Codex tasks need the Mac awake, app running, and SSH
reachability to the Pi. When the Mac is away from home, SSH/API failure means
monitoring is unreachable; it must not be reported as proof that AWG is down.
An external always-on notification channel can later consume the same API or
event stream without replacing the monitoring module.

`client.py` is a portable SSH consumer for that notification layer. `poll`
reads API snapshots, advances its private event cursor and persists pending
notices. Repeated polls retain notices until `ack --ids ...` explicitly
acknowledges them. Health and upstream consumers share a lock-protected state
file, but have separate cursors and outboxes. An unreachable gateway is reported
after two health polls; it is distinct from a confirmed tunnel outage. A first
healthy snapshot initializes the baseline quietly. Upstream snapshots also
initialize quietly unless they already contain an update or a fetch error.

```sh
python3 client.py poll --kind health --state /private/path/consumer.json --ssh-config /private/path/ssh-config --target YOUR_GATEWAY_ALIAS
python3 client.py ack --kind health --state /private/path/consumer.json --ids health-event-123
```

Use `--kind updates` for weekly upstream snapshots. Review release notes before
turning a changed candidate into a user-facing recommendation. A prerelease
change alone need not generate a notification. Acknowledge non-actionable
candidates so they do not repeat; keep actionable findings pending until the
notification has been prepared. The admin application can implement its own
consumer without using this script or its state file.

A failed monitor probe does not affect household direct traffic. A failed VPS
cannot be repaired by changing protocols on that same VPS. Physical Pi failure
is a different case: if clients use the Pi as their DHCP gateway, router DHCP
gateway/DNS must be restored to the router and client leases renewed. Existing
guest Wi-Fi is not an independent fallback until verified to bypass the Pi.

## Validation

```sh
python3 -m unittest discover -s scripts/vpn-monitor -v
bash -n scripts/vpn-monitor/install.sh
```

Tests cover debounce/recovery, event cursors, stale status, history retention,
release channels, tag ordering, preservation of update results during outages,
and rejection of an old successful probe after a failed collection. Deployment
validation must additionally verify the real isolated probe, API permissions,
read-only HTTP behavior, unit timers, and unchanged main gateway state.
