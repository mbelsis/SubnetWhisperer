"""
Scheduler service for running scans on schedule
"""
import threading
import logging
from datetime import datetime
from sqlalchemy import update
from app import db, app
from models import ScheduledScan, ScanSession, scheduled_scan_sessions
from ssh_utils import start_scan_session
from subnet_utils import parse_subnet_input
from encryption_utils import decrypt_data

# Configure logging
logger = logging.getLogger(__name__)

class SchedulerService:
    """Service for managing scheduled scans"""
    def __init__(self, check_interval_seconds=60):
        self.check_interval = check_interval_seconds
        self.scheduler_thread = None
        self.stop_event = threading.Event()
        self._lock = threading.Lock()

    @property
    def running(self):
        return self.scheduler_thread is not None and self.scheduler_thread.is_alive()

    def start(self):
        """Start the scheduler service"""
        with self._lock:
            if self.running:
                logger.warning("Scheduler is already running")
                return False

            logger.info("Starting scheduler service")
            self.stop_event.clear()
            self.scheduler_thread = threading.Thread(target=self._run_scheduler, name="scan-scheduler")
            self.scheduler_thread.daemon = True
            self.scheduler_thread.start()
            return True

    def stop(self):
        """Stop the scheduler service"""
        with self._lock:
            if not self.running:
                logger.warning("Scheduler is not running")
                return False

            logger.info("Stopping scheduler service")
            self.stop_event.set()
            self.scheduler_thread.join(timeout=10)
            self.scheduler_thread = None
            return True

    def _run_scheduler(self):
        """Main scheduler loop"""
        logger.info(f"Scheduler running with check interval of {self.check_interval} seconds")

        while not self.stop_event.is_set():
            try:
                with app.app_context():
                    try:
                        self._check_scheduled_scans()
                    finally:
                        db.session.remove()
            except Exception:
                logger.exception("Error in scheduler loop")

            # Wait for the next check interval or until stop_event is set
            self.stop_event.wait(self.check_interval)

    def _claim(self, scheduled_scan, now):
        """Atomically claim a due run so that only one process executes it.

        The UPDATE only succeeds if next_run is still the value we read, so a
        second worker process (or the debug reloader) racing on the same row
        gets rowcount 0 and skips it.
        """
        previous_next_run = scheduled_scan.next_run
        previous_last_run = scheduled_scan.last_run
        scheduled_scan.last_run = now
        new_next_run = scheduled_scan.calculate_next_run(now=now)
        new_is_active = scheduled_scan.is_active
        db.session.expire(scheduled_scan)  # discard in-memory changes; the UPDATE below is authoritative

        result = db.session.execute(
            update(ScheduledScan)
            .where(ScheduledScan.id == scheduled_scan.id,
                   ScheduledScan.next_run == previous_next_run)
            .values(last_run=now, next_run=new_next_run, is_active=new_is_active)
        )
        db.session.commit()
        if result.rowcount != 1:
            logger.info(f"Scheduled scan {scheduled_scan.id} already claimed by another process")
            return False
        logger.debug(f"Claimed scheduled scan {scheduled_scan.id} (previous run {previous_last_run})")
        return True

    def _check_scheduled_scans(self):
        """Check for scheduled scans that need to be executed"""
        current_time = datetime.utcnow()

        # Find active schedules that need to run
        due_ids = [row.id for row in ScheduledScan.query.with_entities(ScheduledScan.id).filter(
            ScheduledScan.is_active == True,  # noqa: E712
            ScheduledScan.next_run <= current_time,
            (ScheduledScan.end_date.is_(None) | (ScheduledScan.end_date >= current_time))
        ).all()]

        for scan_id in due_ids:
            scheduled_scan = db.session.get(ScheduledScan, scan_id)
            if scheduled_scan is None:
                continue
            try:
                # Advance next_run before executing so a failing scan is not retried every minute
                if not self._claim(scheduled_scan, current_time):
                    continue
                scheduled_scan = db.session.get(ScheduledScan, scan_id)
                logger.info(f"Running scheduled scan: {scheduled_scan.name} (ID: {scan_id})")
                self._execute_scheduled_scan(scheduled_scan)
                logger.info(f"Scheduled scan started: {scheduled_scan.name}. Next run at {scheduled_scan.next_run}")
            except Exception:
                db.session.rollback()
                logger.exception(f"Error executing scheduled scan {scan_id}")

    def _execute_scheduled_scan(self, scheduled_scan):
        """Execute a scheduled scan"""
        # Parse subnets to get IP addresses
        errors = []
        ip_addresses = parse_subnet_input(scheduled_scan.subnets, errors=errors)
        for error in errors:
            logger.warning(f"Scheduled scan {scheduled_scan.id}: {error}")
        if not ip_addresses:
            logger.warning(f"No valid IP addresses found for scheduled scan {scheduled_scan.id}")
            return None

        # Get commands
        commands = []
        if scheduled_scan.command_template is not None:
            commands = [c.strip() for c in scheduled_scan.command_template.commands.splitlines() if c.strip()]
        if scheduled_scan.custom_commands:
            commands.extend(c.strip() for c in scheduled_scan.custom_commands.splitlines() if c.strip())

        # Get credentials
        username = scheduled_scan.username
        password = None
        private_key = None
        sudo_password = None
        credential_set_ids = None

        if scheduled_scan.credential_set_id:
            credential_set_ids = [scheduled_scan.credential_set_id]
        elif scheduled_scan.auth_type == 'password' and scheduled_scan.password_encrypted:
            password = decrypt_data(scheduled_scan.password_encrypted)
        elif scheduled_scan.auth_type == 'key' and scheduled_scan.private_key_encrypted:
            private_key = decrypt_data(scheduled_scan.private_key_encrypted)
        else:
            logger.error(f"Scheduled scan {scheduled_scan.id} has no usable credentials; skipping")
            return None

        if scheduled_scan.sudo_password_encrypted:
            sudo_password = decrypt_data(scheduled_scan.sudo_password_encrypted)

        # Create a new scan session linked to this schedule
        scan_session = ScanSession(
            username=username,
            auth_type=scheduled_scan.auth_type,
            collect_server_info=scheduled_scan.collect_server_info,
            collect_detailed_info=scheduled_scan.collect_detailed_info,
            total_ips=len(ip_addresses)
        )
        db.session.add(scan_session)
        db.session.flush()
        db.session.execute(scheduled_scan_sessions.insert().values(
            scheduled_scan_id=scheduled_scan.id, scan_session_id=scan_session.id))
        db.session.commit()

        # Start scan in background
        start_scan_session(
            scan_session_id=scan_session.id,
            ip_addresses=ip_addresses,
            username=username,
            password=password,
            private_key=private_key,
            commands=commands,
            collect_server_info=scheduled_scan.collect_server_info,
            collect_detailed_info=scheduled_scan.collect_detailed_info,
            sudo_password=sudo_password,
            credential_set_ids=credential_set_ids,
            concurrency=scheduled_scan.concurrency or 10,
            port=scheduled_scan.port or 22
        )

        logger.info(f"Scheduled scan {scheduled_scan.id} started with scan session {scan_session.id}")
        return scan_session.id

# Initialize scheduler service
scheduler_service = SchedulerService()

def start_scheduler():
    """Start the scheduler service"""
    return scheduler_service.start()

def stop_scheduler():
    """Stop the scheduler service"""
    return scheduler_service.stop()
