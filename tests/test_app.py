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
            self.db.session.commit()

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
        from datetime import datetime, timedelta
        with self.app.app_context():
            start = datetime.utcnow() + timedelta(days=1)
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


if __name__ == "__main__":
    unittest.main()
