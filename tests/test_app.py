import importlib
import os
import sys
import unittest
from pathlib import Path


TEST_ENCRYPTION_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
ADMIN_PASSWORD = "admin-test-password"
VIEWER_PASSWORD = "viewer-test-password"


def load_app_with_temp_db():
    project_root = Path(__file__).resolve().parents[1]
    instance_dir = project_root / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)
    db_path = instance_dir / "test_suite.db"
    if db_path.exists():
        db_path.unlink()

    os.environ["DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
    os.environ["SESSION_SECRET"] = "test-session-secret"
    os.environ["ENCRYPTION_KEY"] = TEST_ENCRYPTION_KEY
    os.environ["START_SCHEDULER"] = "false"
    os.environ["ADMIN_PASSWORD"] = "initial-admin-pass"

    modules_to_clear = [
        "app",
        "models",
        "forms",
        "ssh_utils",
        "subnet_utils",
        "encryption_utils",
        "scheduler",
        "migrations",
        "migrations.schema",
    ]
    for module_name in modules_to_clear:
        sys.modules.pop(module_name, None)

    app_module = importlib.import_module("app")
    app_module.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )

    return str(db_path), app_module


class AppRoutesTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_path, cls.app_module = load_app_with_temp_db()
        cls.app = cls.app_module.app
        cls.db = cls.app_module.db

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            cls.db.session.remove()
            cls.db.drop_all()
            cls.db.engine.dispose()
        db_file = Path(cls.db_path)
        if db_file.exists():
            db_file.unlink()

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            self.db.session.query(self.app_module.ScanResult).delete()
            self.db.session.execute(self.app_module.db.text("DELETE FROM scheduled_scan_sessions"))
            self.db.session.query(self.app_module.ScanSession).delete()
            self.db.session.query(self.app_module.CommandTemplate).delete()
            self.db.session.query(self.app_module.CredentialSet).delete()
            self.db.session.query(self.app_module.ScheduledScan).delete()
            self.db.session.query(self.app_module.User).delete()
            admin_user = self.app_module.User(username="admin", is_admin=True)
            admin_user.set_password(ADMIN_PASSWORD)
            viewer = self.app_module.User(username="viewer", is_admin=False)
            viewer.set_password(VIEWER_PASSWORD)
            self.db.session.add_all([admin_user, viewer])
            self.db.session.query(self.app_module.AuditLog).delete()
            self.db.session.commit()
        self.app_module.login_throttle._failures.clear()

    def login(self, username="admin", password=ADMIN_PASSWORD):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )

    def test_login_page_loads(self):
        response = self.client.get("/login")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Login", response.data)

    def test_start_scan_requires_subnets(self):
        login_response = self.login()
        self.assertEqual(login_response.status_code, 302)

        response = self.client.post("/start_scan", json={})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": "No data provided"})

    def test_start_scan_rejects_missing_manual_credentials(self):
        login_response = self.login()
        self.assertEqual(login_response.status_code, 302)

        response = self.client.post(
            "/start_scan",
            json={
                "subnets": "192.168.1.10",
                "auth_type": "password",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": "Username is required"})

    def test_scan_results_summary_returns_saved_results(self):
        login_response = self.login()
        self.assertEqual(login_response.status_code, 302)

        with self.app.app_context():
            session = self.app_module.ScanSession(
                username="tester",
                auth_type="password",
                total_ips=2,
                status="completed",
            )
            self.db.session.add(session)
            self.db.session.commit()

            self.db.session.add_all(
                [
                    self.app_module.ScanResult(
                        scan_session_id=session.id,
                        ip_address="192.168.1.10",
                        status_code="success",
                        ssh_status=True,
                        command_status=True,
                    ),
                    self.app_module.ScanResult(
                        scan_session_id=session.id,
                        ip_address="192.168.1.11",
                        status_code="failed",
                        ssh_status=False,
                        command_status=False,
                        error_message="Connection timed out",
                    ),
                ]
            )
            self.db.session.commit()
            session_id = session.id

        response = self.client.get(f"/scan_results/{session_id}")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["summary"]["total"], 2)
        self.assertEqual(payload["summary"]["success"], 1)
        self.assertEqual(payload["summary"]["failed"], 1)

    def test_create_schedule_page_loads_for_authenticated_user(self):
        login_response = self.login()
        self.assertEqual(login_response.status_code, 302)

        response = self.client.get("/schedules/create")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Schedule", response.data)

    def test_logout_requires_post(self):
        self.login()
        self.assertEqual(self.client.get("/logout").status_code, 405)
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 302)

    def test_open_redirect_is_blocked(self):
        response = self.client.post(
            "/login?next=/\\evil.com",
            data={"username": "admin", "password": ADMIN_PASSWORD},
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("evil.com", response.headers["Location"])

    def test_non_admin_cannot_manage_credentials_or_schedules(self):
        self.login("viewer", VIEWER_PASSWORD)
        self.assertEqual(self.client.get("/credentials").status_code, 302)
        self.assertEqual(self.client.get("/schedules").status_code, 302)
        response = self.client.post(
            "/start_scan",
            json={"subnets": "192.168.1.10", "use_credential_sets": True, "multiple_credentials": True},
        )
        self.assertEqual(response.status_code, 403)

    def test_forced_password_change_redirects(self):
        with self.app.app_context():
            user = self.app_module.User.query.filter_by(username="viewer").one()
            user.must_change_password = True
            self.db.session.commit()
        self.login("viewer", VIEWER_PASSWORD)
        response = self.client.get("/results")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/change_password", response.headers["Location"])

    def test_change_password_enforces_minimum_length(self):
        self.login()
        response = self.client.post(
            "/change_password",
            data={"current_password": ADMIN_PASSWORD, "new_password": "short", "confirm_password": "short"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"at least 8 characters", response.data)

    def test_password_change_invalidates_other_sessions(self):
        other = self.app.test_client()
        other.post("/login", data={"username": "viewer", "password": VIEWER_PASSWORD})
        self.assertEqual(other.get("/results").status_code, 200)
        with self.app.app_context():
            user = self.app_module.User.query.filter_by(username="viewer").one()
            user.set_password("a-brand-new-password")
            self.db.session.commit()
        self.assertEqual(other.get("/results").status_code, 302)

    def test_start_scan_rejects_bad_concurrency(self):
        self.login()
        response = self.client.post(
            "/start_scan",
            json={"subnets": "192.168.1.10", "username": "u", "password": "p", "concurrency": "abc"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Concurrency", response.get_json()["error"])

    def test_start_scan_rejects_huge_subnet(self):
        self.login()
        response = self.client.post(
            "/start_scan",
            json={"subnets": "10.0.0.0/8", "username": "u", "password": "p"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Too many", response.get_json()["error"])

    def test_validate_subnets_reports_errors(self):
        self.login()
        response = self.client.post("/validate_subnets", json={"subnets": "10.0.0.1-3\n999.1.1.1"})
        payload = response.get_json()
        self.assertEqual(payload["count"], 3)
        self.assertFalse(payload["valid"])
        self.assertTrue(payload["errors"])

    def test_template_update_and_duplicate_name(self):
        self.login()
        with self.app.app_context():
            first = self.app_module.CommandTemplate(name="one", commands="uptime")
            second = self.app_module.CommandTemplate(name="two", commands="df -h")
            self.db.session.add_all([first, second])
            self.db.session.commit()
            first_id = first.id
        response = self.client.put(f"/template/{first_id}", json={"name": "two", "commands": "uptime"})
        self.assertEqual(response.status_code, 409)
        response = self.client.put(f"/template/{first_id}", json={"name": "renamed", "commands": "uptime"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["template"]["name"], "renamed")

    def test_csv_export_neutralizes_formulas(self):
        self.login()
        with self.app.app_context():
            session = self.app_module.ScanSession(username="t", auth_type="password", total_ips=1, status="completed")
            self.db.session.add(session)
            self.db.session.commit()
            self.db.session.add(self.app_module.ScanResult(
                scan_session_id=session.id, ip_address="10.0.0.1", status_code="failed",
                error_message='=HYPERLINK("http://x","y")'))
            self.db.session.commit()
            session_id = session.id
        response = self.client.get(f"/scan_results/{session_id}/export/csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"'=HYPERLINK", response.data)

    def test_delete_scan(self):
        self.login()
        with self.app.app_context():
            session = self.app_module.ScanSession(username="t", auth_type="password", total_ips=0, status="completed")
            self.db.session.add(session)
            self.db.session.commit()
            session_id = session.id
        self.assertEqual(self.client.delete(f"/api/delete_scan/{session_id}").get_json(), {"success": True})
        self.assertEqual(self.client.delete(f"/api/delete_scan/{session_id}").status_code, 404)

    def test_schedule_next_run_starts_at_start_date(self):
        from datetime import datetime, timedelta, timezone
        with self.app.app_context():
            start = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1)
            schedule = self.app_module.ScheduledScan(
                name="s", subnets="10.0.0.1", username="u", auth_type="password",
                schedule_frequency="daily", start_date=start, is_active=True)
            self.assertEqual(schedule.calculate_next_run(), start)

    def test_initial_admin_password_file_removed_after_change(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "initial_admin_password")
            with open(path, "w") as f:
                f.write("generated\n")
            original = self.app_module.INITIAL_ADMIN_PASSWORD_FILE
            self.app_module.INITIAL_ADMIN_PASSWORD_FILE = path
            try:
                self.login()
                self.client.post("/change_password", data={
                    "current_password": ADMIN_PASSWORD, "new_password": "another-admin-pw",
                    "confirm_password": "another-admin-pw"})
                self.assertFalse(os.path.exists(path))
            finally:
                self.app_module.INITIAL_ADMIN_PASSWORD_FILE = original

    def test_load_private_key_with_passphrase(self):
        import io
        import paramiko
        import ssh_utils
        key = paramiko.RSAKey.generate(2048)
        buf = io.StringIO()
        key.write_private_key(buf, password="s3cret-phrase")
        pem = buf.getvalue()
        loaded = ssh_utils.load_private_key(pem, "s3cret-phrase")
        self.assertEqual(loaded.get_base64(), key.get_base64())
        with self.assertRaisesRegex(paramiko.SSHException, "passphrase-protected"):
            ssh_utils.load_private_key(pem)
        with self.assertRaisesRegex(paramiko.SSHException, "wrong passphrase"):
            ssh_utils.load_private_key(pem, "wrong")


    # ------------------------------------------------------------------
    # Helpers for the hardening tests
    # ------------------------------------------------------------------

    def _user_id(self, username):
        with self.app.app_context():
            return self.app_module.User.query.filter_by(username=username).first().id

    def _make_scan(self, owner_id, status="completed", with_output=True):
        with self.app.app_context():
            scan = self.app_module.ScanSession(username="ssh-user", auth_type="password", total_ips=1,
                                               status=status, owner_id=owner_id)
            self.db.session.add(scan)
            self.db.session.commit()
            result = self.app_module.ScanResult(
                scan_session_id=scan.id, ip_address="10.0.0.5", status_code="success", ssh_status=True,
                command_output='[{"command": "id", "stdout": "uid=0(root)"}]' if with_output else None,
                server_info='{"hostname": "secret-host"}' if with_output else None)
            self.db.session.add(result)
            self.db.session.commit()
            return scan.id, result.id

    # ------------------------------------------------------------------
    # Access control: users only see their own scans
    # ------------------------------------------------------------------

    def test_viewer_cannot_see_other_users_scans(self):
        admin_scan, admin_result = self._make_scan(self._user_id("admin"))
        own_scan, _ = self._make_scan(self._user_id("viewer"))
        orphan_scan, _ = self._make_scan(None)

        self.login("viewer", VIEWER_PASSWORD)
        for url in (f"/scan_results/{admin_scan}", f"/scan_status/{admin_scan}",
                    f"/scan_results/{admin_scan}/export/json",
                    f"/scan_results/{admin_scan}/result/{admin_result}",
                    f"/scan_results/{orphan_scan}"):
            response = self.client.get(url, headers={"Accept": "application/json"})
            self.assertEqual(response.status_code, 404, url)
        self.assertEqual(self.client.get(f"/scan_results/{own_scan}").status_code, 200)

        page = self.client.get("/results").get_data(as_text=True)
        self.assertIn(f'data-scan-id="{own_scan}"', page)
        self.assertNotIn(f'data-scan-id="{admin_scan}"', page)
        self.assertNotIn(f'data-scan-id="{orphan_scan}"', page)

    def test_admin_sees_all_scans(self):
        viewer_scan, _ = self._make_scan(self._user_id("viewer"))
        self.login()
        self.assertEqual(self.client.get(f"/scan_results/{viewer_scan}").status_code, 200)
        self.assertIn(f'data-scan-id="{viewer_scan}"', self.client.get("/results").get_data(as_text=True))

    def test_started_scan_is_owned_by_its_user(self):
        import ssh_utils
        original = ssh_utils.start_scan_session
        self.app_module.ssh_utils.start_scan_session = lambda **kwargs: None
        try:
            self.login("viewer", VIEWER_PASSWORD)
            # The route imports start_scan_session from ssh_utils at call time
            response = self.client.post("/start_scan", json={
                "subnets": "10.1.1.1", "username": "u", "auth_type": "password", "password": "p"})
            self.assertEqual(response.status_code, 200, response.get_json())
            scan_id = response.get_json()["scan_id"]
        finally:
            ssh_utils.start_scan_session = original
        with self.app.app_context():
            scan = self.db.session.get(self.app_module.ScanSession, scan_id)
            self.assertEqual(scan.owner_id, self._user_id("viewer"))

    # ------------------------------------------------------------------
    # Result payloads
    # ------------------------------------------------------------------

    def test_result_list_omits_output_and_detail_includes_it(self):
        scan_id, result_id = self._make_scan(self._user_id("admin"))
        self.login()
        listing = self.client.get(f"/scan_results/{scan_id}").get_json()
        self.assertNotIn("command_output", listing["results"][0])
        self.assertNotIn("server_info", listing["results"][0])
        self.assertEqual(listing["summary"]["success"], 1)
        detail = self.client.get(f"/scan_results/{scan_id}/result/{result_id}").get_json()
        self.assertEqual(detail["server_info"]["hostname"], "secret-host")
        other_scan, _ = self._make_scan(self._user_id("admin"))
        self.assertEqual(self.client.get(f"/scan_results/{other_scan}/result/{result_id}").status_code, 404)

    def test_results_page_shows_counts(self):
        scan_id, _ = self._make_scan(self._user_id("admin"))
        self.login()
        page = self.client.get("/results").get_data(as_text=True)
        self.assertIn('<td class="text-success">1</td>', page)

    # ------------------------------------------------------------------
    # Interrupted scans
    # ------------------------------------------------------------------

    def test_recover_interrupted_scans(self):
        scan_id, result_id = self._make_scan(self._user_id("admin"), status="running")
        with self.app.app_context():
            result = self.db.session.get(self.app_module.ScanResult, result_id)
            result.status_code = "pending"
            self.db.session.commit()
            self.assertEqual(self.app_module.ssh_utils.recover_interrupted_scans(), 1)
            scan = self.db.session.get(self.app_module.ScanSession, scan_id)
            self.assertEqual(scan.status, "interrupted")
            self.assertIsNotNone(scan.completed_at)
            self.assertEqual(self.db.session.get(self.app_module.ScanResult, result_id).status_code, "failed")
        self.login()
        response = self.client.delete(f"/api/delete_scan/{scan_id}")
        self.assertEqual(response.status_code, 200)

    # ------------------------------------------------------------------
    # Login throttling
    # ------------------------------------------------------------------

    def test_login_locks_out_after_repeated_failures(self):
        for _ in range(self.app_module.login_throttle.max_failures):
            self.assertEqual(self.login("admin", "wrong-password").status_code, 200)
        response = self.login()  # correct password, but locked out
        self.assertEqual(response.status_code, 429)
        # The same account from another address is not locked
        other = self.app.test_client()
        response = other.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD},
                              environ_base={"REMOTE_ADDR": "10.9.9.9"})
        self.assertEqual(response.status_code, 302)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def test_audit_log_records_events_and_is_admin_only(self):
        self.login("admin", "wrong-password")
        self.login()
        scan_id, _ = self._make_scan(self._user_id("admin"))
        self.client.delete(f"/api/delete_scan/{scan_id}")
        with self.app.app_context():
            actions = [(e.action, e.outcome) for e in self.app_module.AuditLog.query.order_by("id")]
        self.assertIn(("auth.login", "failure"), actions)
        self.assertIn(("auth.login", "success"), actions)
        self.assertIn(("scan.delete", "success"), actions)
        page = self.client.get("/audit?action=scan.")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"scan.delete", page.data)
        self.assertNotIn(b"auth.login", page.data.split(b"<tbody>")[1])

        viewer = self.app.test_client()
        viewer.post("/login", data={"username": "viewer", "password": VIEWER_PASSWORD})
        self.assertEqual(viewer.get("/audit").status_code, 302)
        self.assertEqual(viewer.get("/settings").status_code, 302)

    # ------------------------------------------------------------------
    # Security headers
    # ------------------------------------------------------------------

    def test_security_headers_and_csp_nonce(self):
        self.login()
        response = self.client.get("/users")
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("frame-ancestors 'none'", csp)
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertIn(f'<script nonce="{nonce}">'.encode(), response.data)
        self.assertNotIn(b"<script>", response.data)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    # ------------------------------------------------------------------
    # Command policy
    # ------------------------------------------------------------------

    def test_denylist_blocks_known_bypasses(self):
        from security_utils import sanitize_command
        for command in ("rm -rf /.", "rm -rf //", "rm -rf /usr/..", "rm -rf ~/",
                        "cat /etc/../etc/shadow", "cat /etc//shadow", "dd if=/etc/shadow",
                        "sudo bash", "sudo -u root bash", "doas sh", "systemctl reboot"):
            for mode in ("enabled", "disabled"):
                with self.subTest(command=command, mode=mode):
                    os.environ["COMMAND_SANITIZATION"] = mode
                    try:
                        self.assertFalse(sanitize_command(command)[0])
                    finally:
                        os.environ.pop("COMMAND_SANITIZATION", None)
        for command in ("rm -rf /tmp/build", "ls -la /etc", "sudo ls /root", "find / -name x",
                        "grep shadow /etc/nsswitch.conf"):
            with self.subTest(command=command):
                self.assertTrue(sanitize_command(command)[0])

    def test_allowlist_mode(self):
        from security_utils import sanitize_command
        os.environ["COMMAND_SANITIZATION"] = "allowlist"
        try:
            approved = {"uptime", "df -h | sort"}
            self.assertTrue(sanitize_command("  uptime ", approved)[0])
            self.assertTrue(sanitize_command("df -h | sort", approved)[0])
            self.assertFalse(sanitize_command("uptime; id", approved)[0])
            self.assertFalse(sanitize_command("uptime", None)[0])  # fails closed

            with self.app.app_context():
                self.db.session.add(self.app_module.CommandTemplate(name="ok", commands="uptime\nhostname"))
                self.db.session.commit()
            self.login("viewer", VIEWER_PASSWORD)
            response = self.client.post("/start_scan", json={
                "subnets": "10.1.1.1", "username": "u", "auth_type": "password", "password": "p",
                "custom_commands": "uptime\ncat /etc/passwd"})
            self.assertEqual(response.status_code, 403)
            self.assertIn("not in an approved command template", response.get_json()["error"])
        finally:
            os.environ.pop("COMMAND_SANITIZATION", None)

    # ------------------------------------------------------------------
    # Scan scope and credential scoping
    # ------------------------------------------------------------------

    def test_scan_scope_rejects_out_of_scope_targets(self):
        import ipaddress
        import subnet_utils
        original = subnet_utils.SCAN_ALLOWED_NETWORKS
        subnet_utils.SCAN_ALLOWED_NETWORKS = [ipaddress.ip_network("10.0.0.0/8")]
        try:
            self.login()
            response = self.client.post("/start_scan", json={
                "subnets": "10.1.1.1, 192.168.1.1", "username": "u", "auth_type": "password", "password": "p"})
            self.assertEqual(response.status_code, 403)
            self.assertIn("192.168.1.1", response.get_json()["error"])
            check = self.client.post("/validate_subnets", json={"subnets": "192.168.1.1"}).get_json()
            self.assertFalse(check["valid"])
        finally:
            subnet_utils.SCAN_ALLOWED_NETWORKS = original

    def test_credential_not_sent_outside_allowed_subnets(self):
        import ipaddress
        import ssh_utils
        calls = []
        original = ssh_utils._connect
        ssh_utils._connect = lambda *a, **k: calls.append(a) or object()
        try:
            cred = {"id": 7, "username": "svc", "auth_type": "password", "password": "pw",
                    "allowed_networks": [ipaddress.ip_network("10.0.0.0/24")], "error": None}
            errors = []
            client, used = ssh_utils._try_connect("192.168.5.5", 22, [cred], errors)
            self.assertIsNone(client)
            self.assertEqual(calls, [])
            self.assertIn("not allowed", errors[0])
            client, used = ssh_utils._try_connect("10.0.0.9", 22, [cred], [])
            self.assertIs(used, cred)
            self.assertEqual(len(calls), 1)
        finally:
            ssh_utils._connect = original

    def test_credential_allowed_subnets_and_clear_sudo(self):
        self.login()
        self.client.post("/add_credential", data={
            "username": "svc", "auth_type": "password", "password": "pw", "sudo_password": "sudo-pw",
            "priority": 1, "allowed_subnets": "10.0.0.0/24\n192.168.1.7"})
        with self.app.app_context():
            cred = self.app_module.CredentialSet.query.filter_by(username="svc").one()
            self.assertEqual(cred.allowed_subnets, "10.0.0.0/24, 192.168.1.7/32")
            self.assertIsNotNone(cred.sudo_password_encrypted)
            cred_id = cred.id
        self.client.post("/edit_credential", data={
            "id": cred_id, "username": "svc", "auth_type": "password", "priority": 1,
            "allowed_subnets": "", "clear_sudo_password": "on"})
        with self.app.app_context():
            cred = self.db.session.get(self.app_module.CredentialSet, cred_id)
            self.assertIsNone(cred.sudo_password_encrypted)
            self.assertIsNone(cred.allowed_subnets)
            self.assertIsNotNone(cred.password_encrypted)
        response = self.client.post("/edit_credential", data={
            "id": cred_id, "username": "svc", "auth_type": "password", "priority": 1,
            "allowed_subnets": "not-a-network"}, follow_redirects=True)
        self.assertIn(b"invalid network", response.data)

    # ------------------------------------------------------------------
    # Session secret file
    # ------------------------------------------------------------------

    def test_session_secret_file_is_shared_not_replaced(self):
        import tempfile
        original_dir = self.app_module.INSTANCE_DIR
        original_env = os.environ.pop("SESSION_SECRET", None)
        with tempfile.TemporaryDirectory() as tmp:
            self.app_module.INSTANCE_DIR = tmp
            try:
                first = self.app_module._get_or_create_secret()
                second = self.app_module._get_or_create_secret()
                self.assertEqual(first, second)
                with open(os.path.join(tmp, ".secret_key")) as f:
                    self.assertEqual(f.read().strip(), first)
            finally:
                self.app_module.INSTANCE_DIR = original_dir
                if original_env is not None:
                    os.environ["SESSION_SECRET"] = original_env


if __name__ == "__main__":
    unittest.main()
