import json
import gc
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import app


class MockUpstreamHandler(BaseHTTPRequestHandler):
    newapi_quota = 4_000_000
    sub2api_balance = 3.5
    last_feishu_payload = None

    def log_message(self, *_args):
        pass

    def send_json(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        routes = {
            "/api/user/groups": {"success": True, "data": {"default": {"ratio": 1}}},
            "/api/user/self/groups": {"success": True, "data": {"default": {"ratio": 1}}},
            "/api/user/self": {
                "success": True,
                "data": {"quota": self.newapi_quota, "used_quota": 500_000},
            },
            "/api/status": {"success": True, "data": {"quota_per_unit": 500_000}},
            "/api/v1/groups/available": {
                "code": 0,
                "data": [{"id": 1, "name": "default", "rate_multiplier": 1}],
            },
            "/api/v1/groups/rates": {"code": 0, "data": {}},
            "/api/v1/user/profile": {
                "code": 0,
                "data": {"balance": self.sub2api_balance, "frozen_balance": 0.5},
            },
        }
        self.send_json(routes.get(self.path, {"code": 404}))

    def do_POST(self):
        if self.path == "/api/v1/auth/login":
            self.send_json({"code": 0, "data": {"access_token": "mock-token"}})
        elif self.path == "/feishu":
            length = int(self.headers.get("Content-Length", "0"))
            self.__class__.last_feishu_payload = json.loads(self.rfile.read(length))
            self.send_json({"code": 0, "msg": "success"})
        else:
            self.send_json({"code": 404})


class BalanceMonitoringTest(unittest.TestCase):
    def setUp(self):
        MockUpstreamHandler.newapi_quota = 4_000_000
        MockUpstreamHandler.sub2api_balance = 3.5
        MockUpstreamHandler.last_feishu_payload = None
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = app.DB_PATH
        self.original_auth_config_path = app.AUTH_CONFIG_PATH
        app.DB_PATH = Path(self.temp_dir.name) / "test.db"
        app.AUTH_CONFIG_PATH = Path(self.temp_dir.name) / "auth.json"
        app.write_auth_config({
            "username": "test-admin",
            "password": "test-password",
            "session_days": 30,
            "session_secret": "test-session-secret",
        })
        app.AUTH_FAILURES.clear()
        app.init_db()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.api_server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        self.api_thread = threading.Thread(target=self.api_server.serve_forever, daemon=True)
        self.api_thread.start()
        self.api_url = f"http://127.0.0.1:{self.api_server.server_port}"
        login_request = urllib.request.Request(
            f"{self.api_url}/api/auth/login",
            data=json.dumps({"username": "test-admin", "password": "test-password"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(login_request) as response:
            self.session_cookie_header = response.headers["Set-Cookie"]
            self.session_cookie = self.session_cookie_header.split(";", 1)[0]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.api_server.shutdown()
        self.api_server.server_close()
        app.DB_PATH = self.original_db_path
        app.AUTH_CONFIG_PATH = self.original_auth_config_path
        app.AUTH_FAILURES.clear()
        gc.collect()
        self.temp_dir.cleanup()

    def add_site(self, platform, threshold, token=""):
        now = app.utc_now_iso()
        return app.db_execute(
            """
            INSERT INTO sites
            (name, base_url, platform, enabled, interval_minutes, login_enabled,
             auth_mode, login_username, login_password, access_token, access_user_id,
             balance_alert_enabled, balance_alert_threshold, status, next_check_at,
             created_at, updated_at)
            VALUES (?, ?, ?, 1, 3, 1, ?, ?, ?, ?, '1', 1, ?, 'unknown', ?, ?, ?)
            """,
            (
                platform,
                f"{self.base_url}/{platform}".replace(f"/{platform}", ""),
                platform,
                "token" if token else "password",
                "user@example.com",
                "password",
                token,
                threshold,
                now,
                now,
                now,
            ),
        )

    def test_newapi_balance_alert_is_deduplicated_and_recovers(self):
        site_id = self.add_site("newapi", 10, token="system-token")
        first = app.detect_site(site_id)
        second = app.detect_site(site_id)
        self.assertEqual(8.0, first["balance"]["amount"])
        self.assertEqual(1, len(app.db_query_all("SELECT id FROM changes WHERE change_type = 'balance_low'")))
        self.assertTrue(app.db_query_one("SELECT balance_alert_active FROM sites WHERE id = ?", (site_id,))["balance_alert_active"])

        MockUpstreamHandler.newapi_quota = 6_000_000
        recovered = app.detect_site(site_id)
        self.assertEqual(12.0, recovered["balance"]["amount"])
        self.assertEqual(1, len(app.db_query_all("SELECT id FROM changes WHERE change_type = 'balance_recovered'")))
        self.assertEqual(3, len(app.db_query_all("SELECT id FROM balance_snapshots WHERE site_id = ?", (site_id,))))
        self.assertEqual([], second["changes"])

    def test_sub2api_profile_balance_is_collected(self):
        site_id = self.add_site("sub2api", 5)
        result = app.detect_site(site_id)
        self.assertEqual(3.5, result["balance"]["amount"])
        site = app.db_query_one("SELECT current_balance, balance_alert_active FROM sites WHERE id = ?", (site_id,))
        self.assertEqual(3.5, site["current_balance"])
        self.assertEqual(1, site["balance_alert_active"])

    def test_site_api_saves_balance_configuration(self):
        body = json.dumps({
            "name": "NewAPI",
            "base_url": self.base_url,
            "platform": "newapi",
            "login_enabled": True,
            "access_token": "system-token",
            "access_user_id": "1",
            "balance_alert_enabled": True,
            "balance_alert_threshold": 12.5,
            "notify_all_groups": False,
            "notify_groups": ["pro专用", "plus/free混合号池"],
        }).encode()
        request = urllib.request.Request(
            f"{self.api_url}/api/sites",
            data=body,
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            result = json.loads(response.read())
        site = app.db_query_one("SELECT * FROM sites WHERE id = ?", (result["id"],))
        self.assertEqual(1, site["balance_alert_enabled"])
        self.assertEqual(12.5, site["balance_alert_threshold"])
        self.assertEqual(["pro专用", "plus/free混合号池"], json.loads(site["notify_groups_json"]))
        update = urllib.request.Request(
            f"{self.api_url}/api/sites/{result['id']}",
            data=json.dumps({"balance_alert_enabled": True, "balance_alert_threshold": 7.25}).encode(),
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method="PUT",
        )
        with urllib.request.urlopen(update):
            pass
        updated = app.db_query_one("SELECT balance_alert_threshold FROM sites WHERE id = ?", (result["id"],))
        self.assertEqual(7.25, updated["balance_alert_threshold"])

    def test_api_requires_login_and_session_cookie_lasts_30_days(self):
        request = urllib.request.Request(f"{self.api_url}/api/sites")
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request)
        self.assertEqual(401, context.exception.code)

        malformed_cookie_request = urllib.request.Request(
            f"{self.api_url}/api/sites",
            headers={"Cookie": f"{app.AUTH_COOKIE_NAME}=not.valid.@@@"},
        )
        with self.assertRaises(urllib.error.HTTPError) as malformed_context:
            urllib.request.urlopen(malformed_cookie_request)
        self.assertEqual(401, malformed_context.exception.code)

        self.assertIn("Max-Age=2592000", self.session_cookie_header)
        self.assertIn("HttpOnly", self.session_cookie_header)
        self.assertIn("SameSite=Strict", self.session_cookie_header)

        authenticated = urllib.request.Request(
            f"{self.api_url}/api/sites",
            headers={"Cookie": self.session_cookie},
        )
        with urllib.request.urlopen(authenticated) as response:
            self.assertEqual(200, response.status)

    def test_notification_changes_are_filtered_by_exact_group_name(self):
        changes = [
            {"change_type": "ratio_changed", "group_name": "pro专用"},
            {"change_type": "ratio_changed", "group_name": "pro专用-备用"},
            {"change_type": "group_removed", "group_name": "plus/free混合号池"},
        ]
        selected_site = {"notify_groups_json": json.dumps(["pro专用", "plus/free混合号池"])}
        filtered = app.filter_notification_changes(selected_site, changes)
        self.assertEqual([changes[0], changes[2]], filtered)
        self.assertEqual(changes, app.filter_notification_changes({"notify_groups_json": None}, changes))

    def test_feishu_webhook_supports_signature(self):
        app.update_notification_settings({
            "feishu_enabled": True,
            "feishu_webhook": f"{self.base_url}/feishu",
            "feishu_secret": "signing-secret",
        })
        ok, error = app.send_feishu_message("test subject", "test body")
        self.assertTrue(ok, error)
        payload = MockUpstreamHandler.last_feishu_payload
        self.assertEqual("text", payload["msg_type"])
        self.assertIn("test subject", payload["content"]["text"])
        self.assertTrue(payload["timestamp"])
        self.assertTrue(payload["sign"])


if __name__ == "__main__":
    unittest.main()
