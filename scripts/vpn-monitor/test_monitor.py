"""Behavior tests for outage debounce, stale data, history and upstream failures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error

SPEC = importlib.util.spec_from_file_location("monitor", Path(__file__).with_name("monitor.py"))
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)
CLIENT_SPEC = importlib.util.spec_from_file_location("client", Path(__file__).with_name("client.py"))
client = importlib.util.module_from_spec(CLIENT_SPEC)
CLIENT_SPEC.loader.exec_module(client)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.config = {"database": str(base / "data.sqlite3"), "failure_threshold": 3,
                       "retention_days": 30, "stale_after_seconds": 900,
                       "updates_result": str(base / "updates.json"),
                       "updates_cache": str(base / "cache.json"),
                       "components": [{"id": "awg", "repo": "example/project", "kind": "tags", "installed": "v1.0"}]}
        self.addCleanup(self.temp.cleanup)

    def sample(self, observation, checked_at=None):
        return {"observation": observation, "reason": observation, "checked_at": checked_at or int(time.time())}

    def test_outage_debounce_recovery_and_event_cursor(self):
        for result in ("up", "down", "up", "down", "down"):
            state = monitor.store_sample(self.config, self.sample(result))
            self.assertEqual(state["status"], "up")
        state = monitor.store_sample(self.config, self.sample("down"))
        self.assertEqual(state["status"], "down")
        monitor.store_sample(self.config, self.sample("down"))
        monitor.store_sample(self.config, self.sample("up"))
        events = monitor.read_database(self.config, "SELECT id,kind,payload FROM events ORDER BY id")
        self.assertEqual([row[1] for row in events], ["state_changed", "state_changed", "recovered"])
        self.assertEqual(json.loads(events[1][2])["status"], "down")
        after = monitor.read_database(self.config, "SELECT id FROM events WHERE id>?", (events[1][0],))
        self.assertEqual(after, [(events[2][0],)])

    def test_stale_is_not_reported_as_healthy(self):
        monitor.store_sample(self.config, self.sample("up", int(time.time()) - 1000))
        self.assertEqual(monitor.status(self.config)["health"]["status"], "stale")

    def test_history_retention(self):
        monitor.store_sample(self.config, self.sample("up", int(time.time()) - 31 * 86400))
        monitor.store_sample(self.config, self.sample("up"))
        self.assertEqual(monitor.read_database(self.config, "SELECT count(*) FROM samples")[0][0], 1)

    def test_release_channels_do_not_recommend_prerelease_as_stable(self):
        result = monitor.select_versions([
            {"tag_name": "v2.0.0-beta.1", "prerelease": True},
            {"tag_name": "v1.2.0", "prerelease": False},
            {"tag_name": "v9.0.0", "draft": True}], "releases", "1.2.0")
        self.assertEqual(result["latest_stable"]["version"], "v1.2.0")
        self.assertFalse(result["update_available"])
        self.assertTrue(result["latest_any"]["prerelease"])

    def test_tag_order_is_numeric_and_non_version_tags_ignored(self):
        result = monitor.select_versions([{"name": "v3.1.20260828"}, {"name": "v3.1.20261012"},
                                          {"name": "experimental"}], "tags", "v3.1.20260828")
        self.assertTrue(result["update_available"])
        self.assertEqual(result["latest_stable"]["version"], "v3.1.20261012")

    def test_upstream_error_preserves_previous_success(self):
        entries = {"entries": [{"name": "v1.1"}], "etag": "test", "fetched_at": int(time.time())}
        with patch.object(monitor, "github_fetch", return_value=entries):
            monitor.check_updates(self.config)
        with patch.object(monitor, "github_fetch", side_effect=urllib.error.URLError("offline")):
            report = monitor.check_updates(self.config)
        self.assertEqual(report["status"], "partial_error")
        self.assertEqual(report["components"][0]["latest_stable"]["version"], "v1.1")
        self.assertEqual(report["components"][0]["fetch_status"], "error")

    def test_stable_release_can_be_older_than_recent_prerelease_page(self):
        self.config["components"][0]["kind"] = "releases"
        recent = {"entries": [{"tag_name": "v2.0-beta.5", "prerelease": True}], "fetched_at": 100}
        stable = {"entries": [{"tag_name": "v1.1", "prerelease": False}], "fetched_at": 100}
        with patch.object(monitor, "github_fetch", side_effect=[recent, stable]):
            report = monitor.check_updates(self.config)
        component = report["components"][0]
        self.assertEqual(component["latest_stable"]["version"], "v1.1")
        self.assertEqual(component["latest_any"]["version"], "v2.0-beta.5")
        self.assertTrue(component["update_available"])

    def test_failed_service_cannot_reuse_old_success(self):
        self.config.update(netcheck_result=str(Path(self.temp.name) / "probe.json"),
                           expected_exit_ip="192.0.2.1", gateway_guard={"expected_mode": "direct"})
        monitor.write_json(self.config["netcheck_result"], {"started_at": 1, "observation": "up"})
        with patch.object(monitor, "gateway_snapshot", return_value={"mode": "direct"}), \
                patch.object(monitor, "run", return_value=type("Result", (), {"returncode": 0})()), \
                patch.object(monitor, "curl_check", return_value=({"ok": False}, "")), \
                patch.object(monitor.socket, "create_connection", side_effect=OSError):
            result = monitor.health_check(self.config)
        self.assertEqual(result["last_observation"], "down")
        self.assertEqual(result["reason"], "isolated_probe_service_failed")

    def test_notification_consumer_deduplicates_events(self):
        state = {"cursor": 1, "last_status": "up"}
        payload = {"status": {"health": {"status": "down", "checked_at": 100}},
                   "events": {"items": [{"id": 2, "kind": "state_changed", "health": {"status": "down"}}],
                              "next_after_id": 2}}
        notices = client.health_notices(state, payload)
        self.assertEqual(notices[0]["id"], "health-event-2")
        self.assertEqual(client.health_notices(state, payload), [])

    def test_unreachable_monitor_is_distinct_from_tunnel_down(self):
        state = {}
        self.assertEqual(client.health_notices(state, None), [])
        self.assertEqual(client.health_notices(state, None)[0]["kind"], "monitor_unreachable")
        self.assertEqual(client.health_notices(state, None), [])
        payload = {"status": {"health": {"status": "up"}}, "events": {"items": [], "next_after_id": 0}}
        self.assertEqual(client.health_notices(state, payload)[0]["kind"], "monitor_reachable")

    def test_automatic_rollback_notice_is_deduplicated_across_healthy_polls(self):
        state = {"last_status": "up"}
        transition = {"kind": "automatic_rollback", "at": 123, "reason": "probe_failed"}
        payload = {"status": {"health": {"status": "up"},
                              "gateway": {"last_transition": transition}},
                   "events": {"items": [], "next_after_id": 0}}
        notices = client.health_notices(state, payload)
        self.assertEqual([row["kind"] for row in notices], ["automatic_rollback"])
        self.assertEqual(notices[0]["transition"]["reason"], "probe_failed")
        self.assertEqual(client.health_notices(state, payload), [])
        transition["at"] = 124
        self.assertEqual(client.health_notices(state, payload)[0]["id"], "rollback-124")


if __name__ == "__main__":
    unittest.main()
