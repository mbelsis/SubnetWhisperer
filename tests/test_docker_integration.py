import importlib
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path


RUN_DOCKER_TESTS = os.environ.get("RUN_DOCKER_TESTS") == "1"
TEST_ENCRYPTION_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="


def run_command(command, cwd):
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def wait_for_healthy(project_root, service_name, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                service_name,
            ],
            cwd=project_root,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip() == "healthy":
            return
        time.sleep(2)
    raise TimeoutError(f"Container {service_name} did not become healthy in time")


def load_app_for_integration(db_name):
    project_root = Path(__file__).resolve().parents[1]
    db_path = project_root / "instance" / db_name
    if db_path.exists():
        db_path.unlink()

    os.environ["DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
    os.environ["SESSION_SECRET"] = "docker-integration-session-secret"
    os.environ["ENCRYPTION_KEY"] = TEST_ENCRYPTION_KEY
    os.environ["START_SCHEDULER"] = "false"

    for module_name in [
        "app",
        "models",
        "forms",
        "ssh_utils",
        "subnet_utils",
        "encryption_utils",
        "migrations.scheduled_scans",
        "migrations.credential_sets",
    ]:
        sys.modules.pop(module_name, None)

    app_module = importlib.import_module("app")
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return db_path, app_module


@unittest.skipUnless(RUN_DOCKER_TESTS, "Set RUN_DOCKER_TESTS=1 to run Docker integration tests.")
class DockerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parents[1]
        cls.compose_file = cls.project_root / "tests" / "docker-compose.integration.yml"
        cls.key_path = cls.project_root / "tests" / "docker" / "keys" / "id_ed25519_valid"

        try:
            run_command(
                ["docker", "compose", "-f", str(cls.compose_file), "up", "-d", "--build"],
                cls.project_root,
            )
        except subprocess.CalledProcessError as exc:
            details = (exc.stderr or exc.stdout or "").strip()
            raise unittest.SkipTest(f"Docker integration environment unavailable: {details}")
        wait_for_healthy(cls.project_root, "subnet-whisperer-ssh-password")
        wait_for_healthy(cls.project_root, "subnet-whisperer-ssh-key")

        cls.password_host = "127.0.0.1"
        cls.password_port = 2222
        cls.key_host = "127.0.0.1"
        cls.key_port = 2223

        cls.db_path, cls.app_module = load_app_for_integration("test_integration.db")
        cls.db = cls.app_module.db
        cls.models = importlib.import_module("models")
        cls.ssh_utils = importlib.import_module("ssh_utils")

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.app_module.app.app_context():
                cls.db.session.remove()
                cls.db.drop_all()
                cls.db.engine.dispose()
        finally:
            subprocess.run(
                ["docker", "compose", "-f", str(cls.compose_file), "down", "--volumes"],
                cwd=cls.project_root,
                check=False,
                capture_output=True,
                text=True,
            )
            if cls.db_path.exists():
                cls.db_path.unlink()

    def setUp(self):
        with self.app_module.app.app_context():
            self.db.session.query(self.models.ScanResult).delete()
            self.db.session.query(self.models.ScanSession).delete()
            self.db.session.commit()

    def create_scan_session(self, username, auth_type):
        with self.app_module.app.app_context():
            session = self.models.ScanSession(
                username=username,
                auth_type=auth_type,
                total_ips=1,
                status="running",
            )
            self.db.session.add(session)
            self.db.session.commit()
            return session.id

    def test_password_container_executes_commands(self):
        session_id = self.create_scan_session("scanner", "password")

        self.ssh_utils.execute_ssh_commands(
            ip=self.password_host,
            username="scanner",
            password="scannerpass",
            commands=["echo password-target"],
            scan_session_id=session_id,
            port=self.password_port,
        )

        with self.app_module.app.app_context():
            result = self.models.ScanResult.query.filter_by(scan_session_id=session_id).one()

        self.assertEqual(result.status_code, "success")
        self.assertTrue(result.ssh_status)
        output = json.loads(result.command_output)
        self.assertEqual(output[0]["exit_status"], 0)
        self.assertIn("password-target", output[0]["stdout"])

    def test_key_container_executes_commands(self):
        session_id = self.create_scan_session("scanner", "key")

        self.ssh_utils.execute_ssh_commands(
            ip=self.key_host,
            username="scanner",
            private_key=self.key_path.read_text(),
            commands=["echo key-target"],
            scan_session_id=session_id,
            port=self.key_port,
        )

        with self.app_module.app.app_context():
            result = self.models.ScanResult.query.filter_by(scan_session_id=session_id).one()

        self.assertEqual(result.status_code, "success")
        self.assertTrue(result.ssh_status)
        output = json.loads(result.command_output)
        self.assertEqual(output[0]["exit_status"], 0)
        self.assertIn("key-target", output[0]["stdout"])

    def test_start_scan_session_marks_parent_complete(self):
        with self.app_module.app.app_context():
            session = self.models.ScanSession(
                username="scanner",
                auth_type="password",
                total_ips=1,
                status="running",
            )
            self.db.session.add(session)
            self.db.session.commit()
            session_id = session.id

        thread = self.ssh_utils.start_scan_session(
            scan_session_id=session_id,
            ip_addresses=[self.password_host],
            username="scanner",
            password="scannerpass",
            commands=["echo threaded-target"],
            concurrency=1,
            port=self.password_port,
        )
        thread.join(timeout=30)

        with self.app_module.app.app_context():
            refreshed = self.models.ScanSession.query.get(session_id)
            result = self.models.ScanResult.query.filter_by(scan_session_id=session_id).one()

        self.assertFalse(thread.is_alive())
        self.assertEqual(refreshed.status, "completed")
        self.assertTrue(refreshed.completed_at is not None)
        self.assertEqual(result.status_code, "success")


if __name__ == "__main__":
    unittest.main()
