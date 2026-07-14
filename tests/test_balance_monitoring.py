import json
import gc
import sqlite3
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
    last_qq_payload = None
    last_qq_authorization = None

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
        elif self.path == "/qq-notify":
            length = int(self.headers.get("Content-Length", "0"))
            self.__class__.last_qq_payload = json.loads(self.rfile.read(length))
            self.__class__.last_qq_authorization = self.headers.get("Authorization")
            self.send_json({"success": True, "group_id": self.__class__.last_qq_payload.get("group_id"), "message_id": 42})
        else:
            self.send_json({"code": 404})


class BalanceMonitoringTest(unittest.TestCase):
    def setUp(self):
        MockUpstreamHandler.newapi_quota = 4_000_000
        MockUpstreamHandler.sub2api_balance = 3.5
        MockUpstreamHandler.last_feishu_payload = None
        MockUpstreamHandler.last_qq_payload = None
        MockUpstreamHandler.last_qq_authorization = None
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
        with urllib.request.urlopen(f"{self.api_url}/api/version") as response:
            version_payload = json.loads(response.read())
        self.assertEqual(app.APP_VERSION, version_payload["version"])

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

    def test_sub2api_group_name_ratio_change_is_matched_by_stable_id(self):
        old_groups = {
            "Codex - 0.02x（福利低价）": {
                "id": 7,
                "ratio": 0.02,
                "ratio_type": "number",
                "desc": "",
            },
        }
        new_groups = {
            "Codex - 0.015x（福利低价）": {
                "id": 7,
                "ratio": 0.015,
                "ratio_type": "number",
                "desc": "",
            },
        }
        changes = app.diff_groups(old_groups, new_groups)
        self.assertEqual(1, len(changes))
        self.assertEqual("ratio_changed", changes[0]["change_type"])
        self.assertEqual("Codex - 0.015x（福利低价）", changes[0]["group_name"])
        self.assertEqual("Codex - 0.02x（福利低价）", changes[0]["old_group_name"])
        self.assertEqual(-25.0, changes[0]["change_percent"])
        self.assertEqual("0.02x", app.format_change_value(changes[0]["old_value"]))
        self.assertEqual("0.015x", app.format_change_value(changes[0]["new_value"]))

    def test_sub2api_group_pure_rename_is_not_add_and_remove(self):
        old_groups = {"旧名称": {"id": 9, "ratio": 1, "desc": ""}}
        new_groups = {"新名称": {"id": 9, "ratio": 1, "desc": ""}}
        changes = app.diff_groups(old_groups, new_groups)
        self.assertEqual(["group_renamed"], [change["change_type"] for change in changes])
        self.assertEqual("旧名称", changes[0]["old_value"])
        self.assertEqual("新名称", changes[0]["new_value"])

    def test_group_rename_keeps_selected_notification_scope(self):
        site_id = self.add_site("sub2api", 5)
        app.db_execute(
            "UPDATE sites SET notify_groups_json = ? WHERE id = ?",
            (json.dumps(["Codex - 0.02x（福利低价）"]), site_id),
        )
        site = app.db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,))
        changes = [{
            "change_type": "ratio_changed",
            "group_name": "Codex - 0.015x（福利低价）",
            "old_group_name": "Codex - 0.02x（福利低价）",
            "new_group_name": "Codex - 0.015x（福利低价）",
        }]
        updated_site = app.remap_notification_group_names(site, changes)
        self.assertEqual(changes, app.filter_notification_changes(updated_site, changes))
        stored = app.db_query_one("SELECT notify_groups_json FROM sites WHERE id = ?", (site_id,))
        self.assertEqual(["Codex - 0.015x（福利低价）"], json.loads(stored["notify_groups_json"]))

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

    def test_qq_notification_uses_fixed_group_and_bearer_token(self):
        app.update_notification_settings({
            "qq_enabled": True,
            "qq_api_url": f"{self.base_url}/qq-notify",
            "qq_api_token": "notify-secret",
            "qq_group_id": "123456789",
        })
        ok, error = app.send_qq_message("test subject", "test body")
        self.assertTrue(ok, error)
        self.assertEqual("Bearer notify-secret", MockUpstreamHandler.last_qq_authorization)
        self.assertEqual({
            "group_id": "123456789",
            "subject": "test subject",
            "message": "test body",
        }, MockUpstreamHandler.last_qq_payload)
        settings = app.notification_settings_payload()
        self.assertTrue(settings["qq_has_api_token"])
        self.assertNotIn("qq_api_token", settings)
        self.assertEqual("123456789", settings["qq_group_id"])

    def test_qq_notification_configuration_rejects_invalid_group(self):
        with self.assertRaisesRegex(ValueError, "有效的 QQ 群号"):
            app.update_notification_settings({
                "qq_enabled": True,
                "qq_api_url": f"{self.base_url}/qq-notify",
                "qq_api_token": "notify-secret",
                "qq_group_id": "not-a-group",
            })

    def test_bot_balance_api_requires_notification_token(self):
        site_id = self.add_site("sub2api", 5)
        app.db_execute(
            "UPDATE sites SET name = ?, current_balance = ?, balance_currency = ?, balance_last_check_at = ? WHERE id = ?",
            ("余额测试站", 12.34, "USD", app.utc_now_iso(), site_id),
        )
        app.update_notification_settings({
            "qq_enabled": True,
            "qq_api_url": f"{self.base_url}/qq-notify",
            "qq_api_token": "balance-secret",
            "qq_group_id": "123456789",
        })

        unauthorized = urllib.request.Request(f"{self.api_url}/api/bot/balances")
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(unauthorized)
        self.assertEqual(401, context.exception.code)

        authorized = urllib.request.Request(
            f"{self.api_url}/api/bot/balances",
            headers={"Authorization": "Bearer balance-secret"},
        )
        with urllib.request.urlopen(authorized) as response:
            payload = json.loads(response.read())
        self.assertTrue(payload["success"])
        balance_site = next(item for item in payload["data"] if item["name"] == "余额测试站")
        self.assertEqual(12.34, balance_site["current_balance"])
        self.assertEqual("USD", balance_site["balance_currency"])

    def test_existing_notification_database_is_migrated_for_qq(self):
        connection = sqlite3.connect(app.DB_PATH)
        try:
            connection.execute("DROP TABLE notification_settings")
            connection.execute(
                """
                CREATE TABLE notification_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    email_enabled INTEGER NOT NULL DEFAULT 0,
                    smtp_host TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO notification_settings (id, email_enabled, smtp_host, created_at, updated_at) VALUES (1, 1, 'smtp.example.com', ?, ?)",
                (app.utc_now_iso(), app.utc_now_iso()),
            )
            connection.commit()
        finally:
            connection.close()

        app.init_db()
        migrated = app.get_notification_settings()
        self.assertEqual("smtp.example.com", migrated["smtp_host"])
        self.assertEqual(0, migrated["qq_enabled"])
        self.assertIn("qq_api_token", migrated)


if __name__ == "__main__":
    unittest.main()
