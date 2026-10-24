import json
import gc
import re
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import app


class MockUpstreamHandler(BaseHTTPRequestHandler):
    newapi_quota = 4_000_000
    newapi_today_quota = 1_250_000
    sub2api_balance = 3.5
    sub2api_today_cost = 1.75
    sub2api_stats_total_cost = 2.25
    sub2api_dashboard_supported = True
    sub2api_dashboard_requests = 0
    sub2api_stats_requests = 0
    last_sub2api_stats_path = None
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
        original_path = self.path
        path = original_path.split("?", 1)[0]
        api_index = path.find("/api/")
        if api_index > 0:
            path = path[api_index:]
        if path == "/api/v1/usage/dashboard/stats":
            self.__class__.sub2api_dashboard_requests += 1
            if not self.__class__.sub2api_dashboard_supported:
                self.send_json({"code": 404, "message": "route not found"})
                return
        if path == "/api/v1/usage/stats":
            self.__class__.sub2api_stats_requests += 1
            self.__class__.last_sub2api_stats_path = original_path
        routes = {
            "/api/user/groups": {"success": True, "data": {"default": {"ratio": 1}}},
            "/api/user/self/groups": {"success": True, "data": {"default": {"ratio": 1}}},
            "/api/user/self": {
                "success": True,
                "data": {"quota": self.newapi_quota, "used_quota": 500_000},
            },
            "/api/status": {"success": True, "data": {"quota_per_unit": 500_000}},
            "/api/log/self/stat": {
                "success": True,
                "data": {"quota": self.newapi_today_quota},
            },
            "/api/v1/groups/available": {
                "code": 0,
                "data": [{"id": 1, "name": "default", "rate_multiplier": 1}],
            },
            "/api/v1/groups/rates": {"code": 0, "data": {}},
            "/api/v1/user/profile": {
                "code": 0,
                "data": {"balance": self.sub2api_balance, "frozen_balance": 0.5},
            },
            "/api/v1/usage/dashboard/stats": {
                "code": 0,
                "data": {"today_actual_cost": self.sub2api_today_cost},
            },
            "/api/v1/usage/stats": {
                "code": 0,
                "data": {"total_actual_cost": self.sub2api_stats_total_cost},
            },
        }
        self.send_json(routes.get(path, {"code": 404}))

    def do_POST(self):
        path = self.path
        api_index = path.find("/api/")
        if api_index > 0:
            path = path[api_index:]
        if path == "/api/v1/auth/login":
            # Unread request bodies make Windows reset the socket (WinError 10053).
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_json({"code": 0, "data": {"access_token": "mock-token"}})
        elif path == "/feishu":
            length = int(self.headers.get("Content-Length", "0"))
            self.__class__.last_feishu_payload = json.loads(self.rfile.read(length))
            self.send_json({"code": 0, "msg": "success"})
        elif path == "/qq-notify":
            length = int(self.headers.get("Content-Length", "0"))
            self.__class__.last_qq_payload = json.loads(self.rfile.read(length))
            self.__class__.last_qq_authorization = self.headers.get("Authorization")
            self.send_json({"success": True, "group_id": self.__class__.last_qq_payload.get("group_id"), "message_id": 42})
        else:
            self.send_json({"code": 404})


class BalanceMonitoringTest(unittest.TestCase):
    def setUp(self):
        MockUpstreamHandler.newapi_quota = 4_000_000
        MockUpstreamHandler.newapi_today_quota = 1_250_000
        MockUpstreamHandler.sub2api_balance = 3.5
        MockUpstreamHandler.sub2api_today_cost = 1.75
        MockUpstreamHandler.sub2api_stats_total_cost = 2.25
        MockUpstreamHandler.sub2api_dashboard_supported = True
        MockUpstreamHandler.sub2api_dashboard_requests = 0
        MockUpstreamHandler.sub2api_stats_requests = 0
        MockUpstreamHandler.last_sub2api_stats_path = None
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
        site_id = self.add_site("sub2api", 0.5)
        app.db_execute("UPDATE sites SET usage_divisor = 10 WHERE id = ?", (site_id,))
        result = app.detect_site(site_id)
        self.assertEqual(0.35, result["balance"]["amount"])
        self.assertEqual(3.5, result["balance"]["raw_amount"])
        self.assertEqual("CNY", result["balance"]["currency"])
        site = app.db_query_one("SELECT current_balance, balance_alert_active FROM sites WHERE id = ?", (site_id,))
        self.assertEqual(3.5, site["current_balance"])
        self.assertEqual(1, site["balance_alert_active"])
        summary = app.site_summary(app.db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,)))
        self.assertEqual(0.35, summary["current_balance"])
        self.assertEqual(3.5, summary["raw_current_balance"])
        self.assertEqual("CNY", summary["balance_currency"])

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
            "usage_divisor": 10,
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
        self.assertEqual(10, site["usage_divisor"])
        self.assertEqual(["pro专用", "plus/free混合号池"], json.loads(site["notify_groups_json"]))
        update = urllib.request.Request(
            f"{self.api_url}/api/sites/{result['id']}",
            data=json.dumps({
                "balance_alert_enabled": True,
                "balance_alert_threshold": 7.25,
                "usage_divisor": 5,
            }).encode(),
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method="PUT",
        )
        with urllib.request.urlopen(update):
            pass
        updated = app.db_query_one(
            "SELECT balance_alert_threshold, usage_divisor FROM sites WHERE id = ?",
            (result["id"],),
        )
        self.assertEqual(7.25, updated["balance_alert_threshold"])
        self.assertEqual(5, updated["usage_divisor"])

        invalid_update = urllib.request.Request(
            f"{self.api_url}/api/sites/{result['id']}",
            data=json.dumps({"usage_divisor": 0}).encode(),
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method="PUT",
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(invalid_update)
        self.assertEqual(400, context.exception.code)
        error_payload = json.loads(context.exception.read())
        self.assertIn("大于 0", error_payload["message"])

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

    def test_sub2api_token_expiry_supports_milliseconds_and_proactive_refresh(self):
        expired_ms = int((app.app_now() - app.timedelta(minutes=1)).timestamp() * 1000)
        future_ms = int((app.app_now() + app.timedelta(hours=1)).timestamp() * 1000)
        self.assertTrue(app.sub2api_token_refresh_due(expired_ms))
        self.assertFalse(app.sub2api_token_refresh_due(future_ms))
        self.assertTrue(app.is_sub2api_auth_error({"message": "登录已过期，请重新认证"}))

        refreshed = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
        }
        groups_payload = {"success": True, "data": []}
        with patch.object(app, "sub2api_refresh_token", return_value=(True, refreshed, None)) as refresh_mock:
            with patch.object(app, "fetch_sub2api_groups_by_token", return_value=(True, groups_payload, None)) as fetch_mock:
                ok, payload, error = app.fetch_sub2api_user_groups(
                    "https://sub2api.example",
                    auth_mode="token",
                    access_token="expired-access-token",
                    refresh_token="old-refresh-token",
                    token_expires_at=expired_ms,
                )
        self.assertTrue(ok, error)
        refresh_mock.assert_called_once_with("https://sub2api.example", "old-refresh-token")
        fetch_mock.assert_called_once_with("https://sub2api.example", "new-access-token")
        self.assertEqual("new-refresh-token", payload["refreshed_auth"]["refresh_token"])
        self.assertTrue(payload["refreshed_auth"]["token_expires_at"])

    def test_sub2api_proactive_refresh_failure_falls_back_to_valid_access_token(self):
        expired_at = (app.app_now() - app.timedelta(minutes=1)).isoformat()
        groups_payload = {"success": True, "data": []}
        with patch.object(app, "sub2api_refresh_token", return_value=(False, {"code": 401}, "RT 已过期")) as refresh_mock:
            with patch.object(app, "fetch_sub2api_groups_by_token", return_value=(True, groups_payload, None)) as fetch_mock:
                ok, payload, error = app.fetch_sub2api_user_groups(
                    "https://sub2api.example",
                    auth_mode="token",
                    access_token="still-valid-access-token",
                    refresh_token="expired-refresh-token",
                    token_expires_at=expired_at,
                )
        self.assertTrue(ok, error)
        self.assertIs(groups_payload, payload)
        refresh_mock.assert_called_once()
        fetch_mock.assert_called_once_with("https://sub2api.example", "still-valid-access-token")

    def test_sub2api_chinese_expiry_error_triggers_reactive_refresh(self):
        expired_payload = {"groups": {"code": 401, "message": "登录已过期，请重新认证"}}
        groups_payload = {"success": True, "data": []}
        refreshed = {"access_token": "new-access-token", "refresh_token": "rotated-refresh-token", "expires_in": 3600}
        with patch.object(app, "sub2api_refresh_token", return_value=(True, refreshed, None)) as refresh_mock:
            with patch.object(
                app,
                "fetch_sub2api_groups_by_token",
                side_effect=[(False, expired_payload, "登录已过期"), (True, groups_payload, None)],
            ) as fetch_mock:
                ok, payload, error = app.fetch_sub2api_user_groups(
                    "https://sub2api.example",
                    auth_mode="token",
                    access_token="expired-access-token",
                    refresh_token="old-refresh-token",
                )
        self.assertTrue(ok, error)
        self.assertEqual(2, fetch_mock.call_count)
        refresh_mock.assert_called_once_with("https://sub2api.example", "old-refresh-token")
        self.assertEqual("rotated-refresh-token", payload["refreshed_auth"]["refresh_token"])

    def test_rotated_sub2api_tokens_are_saved_even_when_group_fetch_fails(self):
        site_id = self.add_site("sub2api", 5, token="old-access-token")
        app.db_execute(
            "UPDATE sites SET refresh_token = ?, token_expires_at = ? WHERE id = ?",
            ("old-refresh-token", app.utc_now_iso(), site_id),
        )
        refreshed_auth = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "token_expires_at": (app.app_now() + app.timedelta(hours=1)).isoformat(),
        }
        with patch.object(
            app,
            "fetch_sub2api_user_groups",
            return_value=(False, {"refreshed_auth": refreshed_auth}, "分组请求失败"),
        ):
            result = app.detect_site(site_id)
        self.assertFalse(result["success"])
        site = app.db_query_one(
            "SELECT access_token, refresh_token, token_expires_at FROM sites WHERE id = ?",
            (site_id,),
        )
        self.assertEqual("new-access-token", site["access_token"])
        self.assertEqual("new-refresh-token", site["refresh_token"])
        self.assertEqual(refreshed_auth["token_expires_at"], site["token_expires_at"])

    def test_sub2api_auth_failure_notifies_once_and_rearms_after_recovery(self):
        site_id = self.add_site("sub2api", 5, token="expired-access-token")
        app.db_execute(
            "UPDATE sites SET name = ?, refresh_token = ? WHERE id = ?",
            ("超哥", "expired-refresh-token", site_id),
        )
        auth_failure = {
            "groups": {"groups": {"code": 401, "message": "登录已过期"}},
            "refresh": {"code": 401, "message": "refresh token 已失效"},
        }
        success_payload = {
            "data": [],
            "user_rates": {},
            "balance": {"amount": 10.0, "currency": "USD"},
        }
        with patch.object(
            app,
            "fetch_sub2api_user_groups",
            return_value=(False, auth_failure, "refresh token 已失效"),
        ):
            with patch.object(app, "send_qq_message", return_value=(True, None)) as send_mock:
                app.detect_site(site_id)
                app.detect_site(site_id)
                send_mock.assert_called_once()
                subject, message = send_mock.call_args.args
                self.assertEqual("【超哥】登录状态失效", subject)
                self.assertIn("AT 已失效，自动刷新未能恢复监控", message)

                with patch.object(
                    app,
                    "fetch_sub2api_user_groups",
                    return_value=(True, success_payload, None),
                ):
                    app.detect_site(site_id)
                self.assertEqual(0, app.db_query_one(
                    "SELECT auth_alert_active FROM sites WHERE id = ?", (site_id,),
                )["auth_alert_active"])

                app.detect_site(site_id)
                self.assertEqual(2, send_mock.call_count)

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
            "UPDATE sites SET name = ?, current_balance = ?, balance_currency = ?, balance_last_check_at = ?, usage_divisor = ? WHERE id = ?",
            ("余额测试站", 123.456, "USD", app.utc_now_iso(), 10, site_id),
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
        self.assertEqual(12.35, balance_site["current_balance"])
        self.assertEqual("CNY", balance_site["balance_currency"])
        self.assertEqual(123.456, balance_site["raw_current_balance"])
        self.assertEqual("USD", balance_site["raw_balance_currency"])
        self.assertEqual(10, balance_site["usage_divisor"])

    def test_bot_ratio_api_detects_live_and_filters_selected_groups(self):
        first_id = self.add_site("sub2api", 5)
        app.db_execute("UPDATE sites SET base_url = ? WHERE id = ?", (f"{self.base_url}/first", first_id))
        second_id = self.add_site("newapi", 5, token="system-token")
        app.db_execute(
            "UPDATE sites SET name = ?, notify_groups_json = ? WHERE id = ?",
            ("超哥", json.dumps(["精选分组"]), first_id),
        )
        app.db_execute(
            "UPDATE sites SET name = ?, notify_groups_json = NULL WHERE id = ?",
            ("聪明", second_id),
        )
        app.update_notification_settings({
            "qq_enabled": True,
            "qq_api_url": f"{self.base_url}/qq-notify",
            "qq_api_token": "ratio-secret",
            "qq_group_id": "123456789",
        })

        def fake_detect(site_id):
            groups = {
                "精选分组": {"ratio": 0.001},
                "其他分组": {"ratio": 0.002},
            } if site_id == first_id else {
                "默认分组": {"ratio": 0.003},
            }
            return {"success": True, "message": "ok", "groups": groups, "login_groups": {}}

        request = urllib.request.Request(
            f"{self.api_url}/api/bot/ratios",
            data=b"{}",
            headers={"Authorization": "Bearer ratio-secret", "Content-Type": "application/json"},
            method="POST",
        )
        with patch.object(app, "detect_site", side_effect=fake_detect):
            with urllib.request.urlopen(request) as response:
                payload = json.loads(response.read())
        self.assertTrue(payload["success"])
        self.assertEqual(["超哥", "聪明"], [site["name"] for site in payload["data"]])
        self.assertEqual(["精选分组"], [group["name"] for group in payload["data"][0]["groups"]])
        self.assertEqual(["默认分组"], [group["name"] for group in payload["data"][1]["groups"]])

    def test_bot_today_usage_api_queries_all_enabled_sites(self):
        sub2api_id = self.add_site("sub2api", 5)
        app.db_execute("UPDATE sites SET base_url = ? WHERE id = ?", (f"{self.base_url}/sub2api", sub2api_id))
        newapi_id = self.add_site("newapi", 5, token="system-token")
        app.db_execute("UPDATE sites SET name = ? WHERE id = ?", ("上游A", sub2api_id))
        app.db_execute("UPDATE sites SET name = ? WHERE id = ?", ("上游B", newapi_id))
        app.update_notification_settings({
            "qq_enabled": True,
            "qq_api_url": f"{self.base_url}/qq-notify",
            "qq_api_token": "usage-secret",
            "qq_group_id": "123456789",
        })

        unauthorized = urllib.request.Request(
            f"{self.api_url}/api/bot/usages/today",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(unauthorized)
        self.assertEqual(401, context.exception.code)

        request = urllib.request.Request(
            f"{self.api_url}/api/bot/usages/today",
            data=b"{}",
            headers={"Authorization": "Bearer usage-secret", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            payload = json.loads(response.read())
        self.assertTrue(payload["success"])
        self.assertEqual(["上游A", "上游B"], [site["name"] for site in payload["data"]])
        self.assertEqual([1.75, 2.5], [site["amount"] for site in payload["data"]])
        self.assertTrue(all(site["success"] for site in payload["data"]))
        self.assertTrue(all(site["live_success"] for site in payload["data"]))
        self.assertTrue(all(not site["cached"] for site in payload["data"]))

    def test_site_today_usage_api_queries_one_site_and_reports_cache_fallback(self):
        site_id = self.add_site("sub2api", 5)
        app.db_execute("UPDATE sites SET usage_divisor = 10 WHERE id = ?", (site_id,))
        request = urllib.request.Request(
            f"{self.api_url}/api/sites/{site_id}/usage/today",
            data=b"{}",
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            live = json.loads(response.read())
        self.assertTrue(live["success"])
        self.assertTrue(live["live_success"])
        self.assertFalse(live["cached"])
        self.assertEqual(0.18, live["amount"])
        self.assertEqual(1.75, live["raw_amount"])

        with patch.object(app, "fetch_sub2api_today_usage", return_value=(False, {}, "HTTP 429")):
            with urllib.request.urlopen(request) as response:
                cached = json.loads(response.read())
        self.assertTrue(cached["success"])
        self.assertFalse(cached["live_success"])
        self.assertTrue(cached["cached"])
        self.assertEqual("HTTP 429", cached["error"])
        self.assertEqual(0.18, cached["amount"])

    def test_sub2api_today_usage_auto_switches_and_persists_stats_endpoint(self):
        site_id = self.add_site("sub2api", 5)
        MockUpstreamHandler.sub2api_dashboard_supported = False

        first = app.today_usage_for_site(app.db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,)))

        self.assertTrue(first["live_success"])
        self.assertEqual(2.25, first["raw_amount"])
        self.assertEqual("stats", first["sub2api_usage_endpoint"])
        self.assertTrue(first["endpoint_switched"])
        self.assertEqual(1, MockUpstreamHandler.sub2api_dashboard_requests)
        self.assertEqual(1, MockUpstreamHandler.sub2api_stats_requests)
        saved = app.db_query_one("SELECT sub2api_usage_endpoint FROM sites WHERE id = ?", (site_id,))
        self.assertEqual("stats", saved["sub2api_usage_endpoint"])

        stats_url = urllib.parse.urlparse(MockUpstreamHandler.last_sub2api_stats_path)
        stats_query = urllib.parse.parse_qs(stats_url.query)
        self.assertEqual([app.app_now().date().isoformat()], stats_query["start_date"])
        self.assertEqual(stats_query["start_date"], stats_query["end_date"])
        self.assertEqual([app.APP_TIMEZONE_NAME], stats_query["timezone"])

        second = app.today_usage_for_site(app.db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,)))
        self.assertTrue(second["live_success"])
        self.assertFalse(second["endpoint_switched"])
        self.assertEqual(1, MockUpstreamHandler.sub2api_dashboard_requests)
        self.assertEqual(2, MockUpstreamHandler.sub2api_stats_requests)

        update = urllib.request.Request(
            f"{self.api_url}/api/sites/{site_id}",
            data=json.dumps({"sub2api_usage_endpoint": "dashboard"}).encode(),
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method="PUT",
        )
        with urllib.request.urlopen(update):
            pass
        restored = app.db_query_one("SELECT sub2api_usage_endpoint FROM sites WHERE id = ?", (site_id,))
        self.assertEqual("dashboard", restored["sub2api_usage_endpoint"])

    def test_site_auth_api_uses_saved_secrets_without_exposing_them(self):
        sub2api_id = self.add_site("sub2api", 5)
        sub2api_request = urllib.request.Request(
            f"{self.api_url}/api/sites/{sub2api_id}/auth/test",
            data=json.dumps({
                "platform": "sub2api",
                "base_url": self.base_url,
                "auth_mode": "password",
                "login_username": "user@example.com",
                "login_password": "",
            }).encode(),
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method="POST",
        )
        with patch.object(app, "probe_sub2api_groups", return_value={
            "success": True,
            "message": "ok",
            "groups_count": 1,
            "groups": {"default": {"ratio": 1}},
        }) as probe_mock:
            with urllib.request.urlopen(sub2api_request) as response:
                sub2api_result = json.loads(response.read())
        self.assertTrue(sub2api_result["success"])
        self.assertTrue(sub2api_result["used_saved_credentials"])
        self.assertNotIn("access_token", json.dumps(sub2api_result))
        probe_mock.assert_called_once_with(
            self.base_url,
            username="user@example.com",
            password="password",
            auth_mode="password",
            access_token="",
            refresh_token="",
            token_expires_at=None,
        )

        app.db_execute("DELETE FROM sites WHERE id = ?", (sub2api_id,))
        sub2api_token_id = self.add_site("sub2api", 5, token="saved-auth-token")
        sub2api_token_site = app.db_query_one("SELECT * FROM sites WHERE id = ?", (sub2api_token_id,))
        with patch.object(app, "probe_sub2api_groups", return_value={
            "success": True,
            "message": "ok",
            "groups_count": 1,
            "groups": {"default": {"ratio": 1}},
        }) as token_probe_mock:
            sub2api_token_result = app.test_site_authentication(sub2api_token_site, {
                "auth_mode": "token",
                "access_token": "",
            })
        self.assertTrue(sub2api_token_result["success"])
        self.assertTrue(sub2api_token_result["used_saved_credentials"])
        token_probe_mock.assert_called_once_with(
            self.base_url,
            username="user@example.com",
            password="",
            auth_mode="token",
            access_token="saved-auth-token",
            refresh_token="",
            token_expires_at=None,
        )

        app.db_execute("DELETE FROM sites WHERE id = ?", (sub2api_token_id,))
        newapi_id = self.add_site("newapi", 5, token="saved-system-token")
        newapi_request = urllib.request.Request(
            f"{self.api_url}/api/sites/{newapi_id}/auth/test",
            data=json.dumps({
                "platform": "newapi",
                "base_url": self.base_url,
                "access_token": "",
                "access_user_id": "1",
            }).encode(),
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method="POST",
        )
        with patch.object(
            app,
            "fetch_newapi_groups_with_access_token",
            return_value=(True, {"success": True, "data": {"default": {"ratio": 1}}}, None),
        ) as fetch_mock:
            with urllib.request.urlopen(newapi_request) as response:
                newapi_result = json.loads(response.read())
        self.assertTrue(newapi_result["success"])
        self.assertTrue(newapi_result["used_saved_credentials"])
        fetch_mock.assert_called_once_with(self.base_url, "saved-system-token", "1")

    def test_saved_auth_test_persists_rotated_tokens_without_returning_them(self):
        site_id = self.add_site("sub2api", 5, token="old-access-token")
        app.db_execute(
            "UPDATE sites SET refresh_token = ?, token_expires_at = ? WHERE id = ?",
            ("old-refresh-token", "2020-01-01T00:00:00+08:00", site_id),
        )
        site = app.db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,))
        refreshed_auth = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "token_expires_at": "2030-01-01T00:00:00+08:00",
        }
        with patch.object(app, "probe_sub2api_groups", return_value={
            "success": True,
            "message": "ok",
            "groups_count": 1,
            "groups": {"default": {"ratio": 1}},
            "refreshed_auth": refreshed_auth,
        }):
            result = app.test_site_authentication(site, {})
        self.assertTrue(result["success"])
        self.assertTrue(result["auth_updated"])
        self.assertNotIn("refreshed_auth", result)
        updated = app.db_query_one(
            "SELECT access_token, refresh_token, token_expires_at FROM sites WHERE id = ?",
            (site_id,),
        )
        self.assertEqual("new-access-token", updated["access_token"])
        self.assertEqual("new-refresh-token", updated["refresh_token"])
        self.assertEqual("2030-01-01T00:00:00+08:00", updated["token_expires_at"])

    def test_today_usage_uses_same_day_cache_when_live_query_fails(self):
        sub2api_id = self.add_site("sub2api", 5)
        app.db_execute("UPDATE sites SET base_url = ? WHERE id = ?", (f"{self.base_url}/sub2api", sub2api_id))
        newapi_id = self.add_site("newapi", 5, token="system-token")

        first = app.bot_today_usage_payload()
        first_by_id = {site["id"]: site for site in first}
        self.assertEqual(1.75, first_by_id[sub2api_id]["amount"])
        self.assertEqual(2.5, first_by_id[newapi_id]["amount"])

        with patch.object(app, "fetch_sub2api_today_usage", return_value=(False, {}, "HTTP 403")), \
             patch.object(app, "fetch_newapi_today_usage", return_value=(False, {}, "请求超时")):
            fallback = app.bot_today_usage_payload()

        fallback_by_id = {site["id"]: site for site in fallback}
        for site_id in (sub2api_id, newapi_id):
            self.assertTrue(fallback_by_id[site_id]["success"])
            self.assertFalse(fallback_by_id[site_id]["live_success"])
            self.assertTrue(fallback_by_id[site_id]["cached"])
            self.assertEqual(first_by_id[site_id]["amount"], fallback_by_id[site_id]["amount"])
            self.assertEqual(first_by_id[site_id]["fetched_at"], fallback_by_id[site_id]["fetched_at"])

    def test_today_usage_applies_current_divisor_to_live_and_cached_raw_amount(self):
        site_id = self.add_site("newapi", 5, token="system-token")
        app.db_execute("UPDATE sites SET usage_divisor = 10 WHERE id = ?", (site_id,))

        live = app.bot_today_usage_payload()[0]
        self.assertEqual(2.5, live["raw_amount"])
        self.assertEqual(10, live["usage_divisor"])
        self.assertEqual(0.25, live["amount"])
        self.assertEqual("CNY", live["currency"])
        self.assertEqual("USD", live["raw_currency"])

        app.db_execute("UPDATE sites SET usage_divisor = 5 WHERE id = ?", (site_id,))
        with patch.object(app, "fetch_newapi_today_usage", return_value=(False, {}, "HTTP 403")):
            cached = app.bot_today_usage_payload()[0]

        self.assertTrue(cached["cached"])
        self.assertEqual(2.5, cached["raw_amount"])
        self.assertEqual(5, cached["usage_divisor"])
        self.assertEqual(0.5, cached["amount"])
        self.assertEqual("CNY", cached["currency"])
        self.assertEqual("USD", cached["raw_currency"])

        self.assertEqual(0.83, app.converted_money_amount(2.5, 3))
        self.assertEqual(2.68, app.converted_money_amount(2.675, 1))

    def test_today_usage_does_not_use_previous_day_cache(self):
        site_id = self.add_site("newapi", 5, token="system-token")
        app.save_daily_usage_cache(site_id, "2000-01-01", 99.0, "USD", "2000-01-01T12:00:00+08:00")

        with patch.object(app, "fetch_newapi_today_usage", return_value=(False, {}, "HTTP 403")):
            result = app.bot_today_usage_payload()

        self.assertEqual(1, len(result))
        self.assertFalse(result[0]["success"])
        self.assertFalse(result[0]["cached"])
        self.assertIsNone(result[0]["amount"])

    def test_today_usage_falls_back_to_valid_sub2api_token_when_proactive_refresh_fails(self):
        site = {
            "id": 99,
            "base_url": self.base_url,
            "auth_mode": "token",
            "access_token": "still-valid-token",
            "refresh_token": "expired-refresh-token",
            "token_expires_at": "2020-01-01T00:00:00+08:00",
        }
        with patch.object(app, "sub2api_refresh_token", return_value=(False, {}, "刷新失败")):
            ok, usage, error = app.fetch_sub2api_today_usage(site)
        self.assertTrue(ok, error)
        self.assertEqual(1.75, usage["amount"])

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

    def api_request(self, path, method="GET", body=None):
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
            method=method,
        )
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read())

    def test_report_groups_order_bot_balance_payload(self):
        site_ids = []
        for name in ("一号", "二号", "三号"):
            site_id = self.add_site("newapi", 5, token="t")
            app.db_execute("UPDATE sites SET name = ?, base_url = ? WHERE id = ?", (name, f"{self.base_url}/{name}", site_id))
            site_ids.append(site_id)
        first, second, third = site_ids

        drawing = self.api_request("/api/report-groups", "POST", {"name": "画图"})["id"]
        domestic = self.api_request("/api/report-groups", "POST", {"name": "国产"})["id"]
        self.api_request("/api/report-groups/order", "PUT", {"group_ids": [domestic, drawing]})
        self.api_request("/api/sites/order", "PUT", {"layout": [
            {"group_id": domestic, "site_ids": [third]},
            {"group_id": drawing, "site_ids": [second, first]},
            {"group_id": None, "site_ids": []},
        ]})

        payload = app.bot_balance_payload()
        self.assertEqual(["三号", "二号", "一号"], [site["name"] for site in payload])
        self.assertEqual(["国产", "画图", "画图"], [site["group_name"] for site in payload])

        self.api_request(f"/api/report-groups/{drawing}", "DELETE")
        payload = app.bot_balance_payload()
        self.assertEqual(["三号", "二号", "一号"], [site["name"] for site in payload])
        self.assertEqual(["国产", None, None], [site["group_name"] for site in payload])

    def test_report_group_validation_and_site_assignment(self):
        group_id = self.api_request("/api/report-groups", "POST", {"name": "claude"})["id"]
        for bad_name in ("", "带 空格", "claude", "Claude", "未分组"):
            with self.assertRaises(urllib.error.HTTPError) as context:
                self.api_request("/api/report-groups", "POST", {"name": bad_name})
            self.assertEqual(400, context.exception.code)

        site_id = self.add_site("newapi", 5, token="t")
        self.api_request(f"/api/sites/{site_id}", "PUT", {"report_group_id": group_id})
        summary = next(site for site in self.api_request("/api/sites")["data"] if site["id"] == site_id)
        self.assertEqual(group_id, summary["report_group_id"])
        self.assertEqual("claude", summary["report_group_name"])

        with self.assertRaises(urllib.error.HTTPError) as context:
            self.api_request(f"/api/sites/{site_id}", "PUT", {"report_group_id": 9999})
        self.assertEqual(400, context.exception.code)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.api_request("/api/sites/order", "PUT", {"layout": [{"group_id": None, "site_ids": []}]})
        self.assertEqual(400, context.exception.code)

    def test_bot_settings_roundtrip_and_bot_config_endpoint(self):
        saved = self.api_request("/api/bot-settings", "PUT", {
            "aliases": [{"alias": "利润", "target": "  查利润   画图 "}],
            "templates": {
                "profit_title": "今日利润",
                "balance_title": app.DEFAULT_BOT_TEMPLATES["balance_title"],
                "profit_separator": "",
            },
        })["data"]
        self.assertEqual([{"alias": "利润", "target": "查利润 画图"}], saved["aliases"])
        self.assertEqual({"profit_title": "今日利润", "profit_separator": ""}, saved["template_overrides"])
        self.assertEqual("今日利润", saved["templates"]["profit_title"])
        self.assertEqual(app.DEFAULT_BOT_TEMPLATES["balance_title"], saved["templates"]["balance_title"])

        self.assertEqual(5.0, saved["negative_quota_threshold"])

        saved = self.api_request("/api/bot-settings", "PUT", {"negative_quota_threshold": "12.5"})["data"]
        self.assertEqual(12.5, saved["negative_quota_threshold"])
        self.assertEqual([{"alias": "利润", "target": "查利润 画图"}], saved["aliases"])

        self.api_request("/api/bot-settings", "PUT", {"aliases": []})
        self.assertEqual("今日利润", app.bot_settings_payload()["templates"]["profit_title"])
        self.assertEqual(12.5, app.bot_settings_payload()["negative_quota_threshold"])

        app.update_notification_settings({
            "qq_enabled": True,
            "qq_api_url": f"{self.base_url}/qq-notify",
            "qq_api_token": "config-secret",
            "qq_group_id": "123456789",
        })
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(f"{self.api_url}/api/bot/config")
        self.assertEqual(401, context.exception.code)
        request = urllib.request.Request(f"{self.api_url}/api/bot/config", headers={"Authorization": "Bearer config-secret"})
        with urllib.request.urlopen(request) as response:
            config = json.loads(response.read())["data"]
        self.assertEqual([], config["aliases"])
        self.assertEqual("今日利润", config["templates"]["profit_title"])
        self.assertEqual(set(app.DEFAULT_BOT_TEMPLATES), set(config["templates"]))
        self.assertEqual(12.5, config["negative_quota_threshold"])

    def test_bot_settings_validation(self):
        invalid_bodies = [
            {"aliases": [{"alias": "带 空格", "target": "查利润"}]},
            {"aliases": [{"alias": "利润", "target": ""}]},
            {"aliases": [{"alias": "利润", "target": "查利润"}, {"alias": "利润", "target": "查余额"}]},
            {"aliases": [{"alias": "查利润", "target": "查利润 画图"}]},
            {"templates": {"unknown_key": "x"}},
            {"templates": {"profit_footer": "利润 {profitt}"}},
            {"templates": {"profit_title": "x" * (app.MAX_BOT_TEMPLATE_LENGTH + 1)}},
            {"templates": {"profit_title": 5}},
            {"aliases": [{"alias": "查余额", "target": "查利润"}]},
            {"aliases": [{"alias": "余额", "target": "看余额"}]},
            {"negative_quota_threshold": -1},
            {"negative_quota_threshold": "abc"},
            {"negative_quota_threshold": None},
            {"negative_quota_threshold": True},
            {"negative_quota_threshold": app.MAX_NEGATIVE_QUOTA_THRESHOLD + 1},
        ]
        for body in invalid_bodies:
            with self.subTest(body=body):
                with self.assertRaises(urllib.error.HTTPError) as context:
                    self.api_request("/api/bot-settings", "PUT", body)
                self.assertEqual(400, context.exception.code)
        self.assertEqual([], app.bot_settings_payload()["aliases"])
        self.assertEqual(app.DEFAULT_NEGATIVE_QUOTA_THRESHOLD, app.bot_settings_payload()["negative_quota_threshold"])

    def test_default_templates_match_bot_project(self):
        bot_source = Path(app.APP_DIR).parent / "qq-monitor-bot" / "src" / "notification-api.mjs"
        if not bot_source.exists():
            self.skipTest("qq-monitor-bot checkout not found next to this project")
        text = bot_source.read_text(encoding="utf-8")
        block = text.split("export const DEFAULT_TEMPLATES = Object.freeze({", 1)[1].split("})", 1)[0]
        bot_defaults = {
            key: value.encode("utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8")
            for key, value in re.findall(r"^\s*(\w+): '((?:[^'\\]|\\.)*)',?$", block, re.MULTILINE)
        }
        self.assertEqual(app.DEFAULT_BOT_TEMPLATES, bot_defaults)
        for key, template in app.DEFAULT_BOT_TEMPLATES.items():
            self.assertEqual([], [n for n in app.TEMPLATE_PLACEHOLDER_PATTERN.findall(template) if n not in app.BOT_TEMPLATE_VARIABLES[key]])

    def test_report_order_saves_groups_and_sites_atomically(self):
        site_id = self.add_site("newapi", 5, token="t")
        first = self.api_request("/api/report-groups", "POST", {"name": "A"})["id"]
        second = self.api_request("/api/report-groups", "POST", {"name": "B"})["id"]
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.api_request("/api/sites/order", "PUT", {
                "group_ids": [second, first],
                "layout": [{"group_id": first, "site_ids": []}],
            })
        self.assertEqual(400, context.exception.code)
        self.assertEqual([first, second], [group["id"] for group in app.list_report_groups()])

        saved = self.api_request("/api/sites/order", "PUT", {
            "group_ids": [second, first],
            "layout": [{"group_id": second, "site_ids": [site_id]}, {"group_id": first, "site_ids": []}],
        })["data"]
        self.assertEqual([second, first], [group["id"] for group in saved])
        self.assertEqual(second, app.db_query_one("SELECT report_group_id FROM sites WHERE id = ?", (site_id,))["report_group_id"])

    def test_malformed_put_and_delete_bodies_return_400(self):
        group_id = self.api_request("/api/report-groups", "POST", {"name": "A"})["id"]
        cases = [
            ("/api/sites/order", b"not json"),
            ("/api/sites/order", b"[]"),
            ("/api/sites/order", json.dumps({"layout": [{"group_id": [1], "site_ids": []}]}).encode()),
            (f"/api/report-groups/{group_id}", b"[]"),
            ("/api/bot-settings", b"not json"),
        ]
        for path, raw in cases:
            with self.subTest(path=path, raw=raw):
                request = urllib.request.Request(
                    f"{self.api_url}{path}",
                    data=raw,
                    headers={"Content-Type": "application/json", "Cookie": self.session_cookie},
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as context:
                    urllib.request.urlopen(request)
                self.assertEqual(400, context.exception.code)
                self.assertFalse(json.loads(context.exception.read())["success"])

    def test_low_balance_notification_includes_upstream_site(self):
        site_id = self.add_site("newapi", 10, token="system-token")
        site = app.db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,))
        with patch.object(app, "send_qq_message") as send_qq, \
                patch.object(app, "send_email_message"), \
                patch.object(app, "send_wecom_message"), \
                patch.object(app, "send_feishu_message"):
            app.record_balance_event(site, "balance_low", 8.0, 10.0, app.utc_now_iso())
        body = send_qq.call_args[0][1]
        self.assertIn(f"上游站点：{site['base_url']}", body)

    def api_error(self, path, method, body):
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.api_request(path, method, body)
        payload = json.loads(context.exception.read())
        context.exception.close()
        return context.exception.code, payload["message"]

    def test_legacy_unique_base_url_is_migrated_without_losing_history(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        conn = sqlite3.connect(legacy_path)
        conn.executescript(
            """
            CREATE TABLE sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL UNIQUE,
                platform TEXT NOT NULL DEFAULT 'newapi',
                enabled INTEGER NOT NULL DEFAULT 1,
                interval_minutes INTEGER NOT NULL DEFAULT 3,
                status TEXT NOT NULL DEFAULT 'unknown',
                last_error TEXT,
                last_check_at TEXT,
                next_check_at TEXT,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                current_groups_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '/api/user/groups',
                groups_json TEXT,
                raw_json TEXT,
                hash TEXT,
                error_message TEXT,
                checked_at TEXT NOT NULL,
                FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            );
            INSERT INTO sites (id, name, base_url, created_at, updated_at) VALUES (7, '主号', 'https://up.example.com', 'x', 'x');
            INSERT INTO snapshots (site_id, status, checked_at) VALUES (7, 'success', 'x');
            """
        )
        conn.commit()
        conn.close()
        app.DB_PATH = legacy_path
        app.init_db()
        app.init_db()
        check = app.connect_db()
        try:
            self.assertFalse(app.sites_base_url_is_unique(check))
            indexes = {row["name"] for row in check.execute("PRAGMA index_list(sites)").fetchall()}
        finally:
            check.close()
        self.assertIn("idx_sites_enabled_next_check", indexes)
        self.assertEqual(1, len(list(Path(self.temp_dir.name).glob("legacy.before-multi-account-*.db"))))
        site = app.db_query_one("SELECT * FROM sites WHERE id = 7")
        self.assertEqual("主号", site["name"])
        self.assertEqual(1, site["notify_public_ratio"])
        self.assertEqual(1, len(app.db_query_all("SELECT id FROM snapshots WHERE site_id = 7")))
        app.db_execute(
            "INSERT INTO sites (name, base_url, created_at, updated_at) VALUES ('小号', 'https://up.example.com', 'x', 'x')"
        )
        self.assertEqual(2, len(app.db_query_all("SELECT id FROM sites WHERE base_url = 'https://up.example.com'")))
        app.db_execute("DELETE FROM sites WHERE id = 7")
        self.assertEqual([], app.db_query_all("SELECT id FROM snapshots WHERE site_id = 7"))

    def newapi_account(self, name, user_id=None, **extra):
        body = {"name": name, "base_url": self.base_url, "platform": "newapi"}
        if user_id is not None:
            body.update({"login_enabled": True, "access_token": f"token-{user_id}", "access_user_id": user_id})
        body.update(extra)
        return body

    def test_same_upstream_allows_different_accounts_but_rejects_same_account(self):
        main_id = self.api_request("/api/sites", "POST", self.newapi_account("主号", "1"))["id"]
        alt_id = self.api_request("/api/sites", "POST", self.newapi_account("小号", "2"))["id"]
        public_id = self.api_request("/api/sites", "POST", self.newapi_account("公开"))["id"]
        self.assertEqual(3, len({main_id, alt_id, public_id}))

        code, message = self.api_error("/api/sites", "POST", self.newapi_account("重复", "1"))
        self.assertEqual(409, code)
        self.assertIn("用户 ID 1", message)
        self.assertIn("主号", message)
        self.assertIn("重复添加", message)

        code, message = self.api_error("/api/sites", "POST", self.newapi_account("公开2", base_url=f"{self.base_url}/"))
        self.assertEqual(409, code)
        self.assertIn("公开", message)

        code, message = self.api_error(f"/api/sites/{alt_id}", "PUT", self.newapi_account("小号", "1"))
        self.assertEqual(409, code)
        self.assertEqual("2", app.db_query_one("SELECT access_user_id FROM sites WHERE id = ?", (alt_id,))["access_user_id"])

        self.api_request(f"/api/sites/{alt_id}", "PUT", {"name": "小号改名", "enabled": False})
        self.api_request(f"/api/sites/{alt_id}", "PUT", self.newapi_account("小号改名", "3"))
        self.assertEqual("3", app.db_query_one("SELECT access_user_id FROM sites WHERE id = ?", (alt_id,))["access_user_id"])

    def test_sub2api_duplicate_accounts_match_username_and_token(self):
        def sub2api(name, **extra):
            return {"name": name, "base_url": self.base_url, "platform": "sub2api", **extra}

        self.api_request("/api/sites", "POST", sub2api("主号", login_username="Main@Example.com", login_password="p"))
        self.api_request("/api/sites", "POST", sub2api("小号", login_username="alt@example.com", login_password="p"))
        code, message = self.api_error("/api/sites", "POST", sub2api("重复", login_username="main@example.com", login_password="p"))
        self.assertEqual(409, code)
        self.assertIn("主号", message)

        self.api_request("/api/sites", "POST", sub2api("令牌号", auth_mode="token", access_token="tok-a", refresh_token="ref-a"))
        self.api_request("/api/sites", "POST", sub2api("令牌号2", auth_mode="token", access_token="tok-b"))
        code, message = self.api_error("/api/sites", "POST", sub2api("令牌重复", auth_mode="token", access_token="tok-c", refresh_token="ref-a"))
        self.assertEqual(409, code)
        self.assertIn("令牌号", message)
        self.assertEqual(4, len(app.db_query_all("SELECT id FROM sites")))

    def test_public_ratio_toggle_mutes_shared_changes_only(self):
        site_id = self.api_request("/api/sites", "POST", self.newapi_account("小号", "2", notify_public_ratio=False))["id"]
        self.assertFalse(app.site_summary(app.db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,)))["notify_public_ratio"])
        app.detect_site(site_id)
        stale = json.dumps({"default": {"ratio": 2, "ratio_type": "number", "desc": ""}})
        app.db_execute("UPDATE snapshots SET groups_json = ? WHERE site_id = ?", (stale, site_id))
        app.db_execute("UPDATE sites SET current_login_groups_json = ? WHERE id = ?", (stale, site_id))

        with patch.object(app, "notify_changes") as notify:
            app.detect_site(site_id)
        pushed = notify.call_args.args[1]
        self.assertEqual(1, len(pushed))
        self.assertTrue(pushed[0]["message"].startswith("认证增强"))
        self.assertEqual(2, len(app.db_query_all("SELECT id FROM changes WHERE site_id = ? AND change_type = 'ratio_changed'", (site_id,))))

        self.api_request(f"/api/sites/{site_id}", "PUT", {"notify_public_ratio": True})
        app.db_execute("UPDATE snapshots SET groups_json = ? WHERE site_id = ?", (stale, site_id))
        app.db_execute("UPDATE sites SET current_login_groups_json = ? WHERE id = ?", (stale, site_id))
        with patch.object(app, "notify_changes") as notify:
            app.detect_site(site_id)
        self.assertEqual(2, len(notify.call_args.args[1]))



class NewApiAuthErrorMessageTest(unittest.TestCase):
    def test_scope_denied_names_missing_scope(self):
        raw = json.dumps({
            "success": False,
            "message": "The access token lacks the required permission: usage:read",
            "code": "ACCESS_TOKEN_SCOPE_DENIED",
            "message_params": {"scope": "usage:read"},
        })
        message = app.newapi_auth_error_message({"status": 403, "raw": raw}, "HTTP 403")
        self.assertIn("usage:read", message)
        self.assertIn("使用记录", message)

    def test_unparseable_body_keeps_fallback(self):
        self.assertEqual("HTTP 502", app.newapi_auth_error_message({"status": 502, "raw": "<html>"}, "HTTP 502"))

    def test_token_in_user_id_field_is_rejected_before_request(self):
        base_url = "http://127.0.0.1:9"
        for ok, _payload, error in (
            app.fetch_newapi_today_usage(base_url, "nap_x", "nap_x", 0, 1),
            app.fetch_newapi_balance(base_url, "nap_x", "nap_x"),
            app.fetch_newapi_groups_with_access_token(base_url, "nap_x", "nap_x"),
        ):
            self.assertFalse(ok)
            self.assertEqual(app.NEWAPI_USER_ID_INVALID_MESSAGE, error)


if __name__ == "__main__":
    unittest.main()
