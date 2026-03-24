import importlib
import os
import sys
import unittest
from pathlib import Path


TEST_ENCRYPTION_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="


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

    modules_to_clear = [
        "app",
        "models",
        "forms",
        "ssh_utils",
        "subnet_utils",
        "encryption_utils",
        "migrations.scheduled_scans",
        "migrations.credential_sets",
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
            admin_user.set_password("admin")
            self.db.session.add(admin_user)
            self.db.session.commit()

    def login(self):
        return self.client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
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


if __name__ == "__main__":
    unittest.main()
