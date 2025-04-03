"""
Scheduler service for running scans on schedule
"""
import threading
import time
import logging
from datetime import datetime, timedelta
import os
from app import db, app
from models import ScheduledScan, ScanSession
from ssh_utils import start_scan_session
from subnet_utils import parse_subnet_input

# Configure logging
logger = logging.getLogger(__name__)

# Function to decrypt sensitive data
def decrypt_data(encrypted_data):
    """Decrypt sensitive data (placeholder for actual encryption)"""
    # In a real application, you'd use proper encryption/decryption
    # For now, we'll just return the data as is
    return encrypted_data

class SchedulerService:
    """Service for managing scheduled scans"""
    def __init__(self, check_interval_seconds=60):
        self.check_interval = check_interval_seconds
        self.scheduler_thread = None
        self.stop_event = threading.Event()
        self.running = False
    
    def start(self):
        """Start the scheduler service"""
        if self.running:
            logger.warning("Scheduler is already running")
            return False
        
        logger.info("Starting scheduler service")
        self.stop_event.clear()
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
        return True
    
    def stop(self):
        """Stop the scheduler service"""
        if not self.running:
            logger.warning("Scheduler is not running")
            return False
        
        logger.info("Stopping scheduler service")
        self.stop_event.set()
        self.scheduler_thread.join(timeout=10)
        self.running = False
        return True
    
    def _run_scheduler(self):
        """Main scheduler loop"""
        logger.info(f"Scheduler running with check interval of {self.check_interval} seconds")
        
        while not self.stop_event.is_set():
            try:
                with app.app_context():
                    self._check_scheduled_scans()
            except Exception as e:
                logger.error(f"Error in scheduler: {str(e)}")
            
            # Wait for the next check interval or until stop_event is set
            self.stop_event.wait(self.check_interval)
    
    def _check_scheduled_scans(self):
        """Check for scheduled scans that need to be executed"""
        current_time = datetime.utcnow()
        
        # Find active schedules that need to run
        scheduled_scans = ScheduledScan.query.filter(
            ScheduledScan.is_active == True,
            ScheduledScan.next_run <= current_time,
            (ScheduledScan.end_date.is_(None) | (ScheduledScan.end_date >= current_time))
        ).all()
        
        for scheduled_scan in scheduled_scans:
            try:
                logger.info(f"Running scheduled scan: {scheduled_scan.name} (ID: {scheduled_scan.id})")
                self._execute_scheduled_scan(scheduled_scan)
                
                # Update next run time
                scheduled_scan.last_run = current_time
                scheduled_scan.next_run = scheduled_scan.calculate_next_run()
                db.session.commit()
                
                logger.info(f"Scheduled scan completed: {scheduled_scan.name}. Next run at {scheduled_scan.next_run}")
            except Exception as e:
                logger.error(f"Error executing scheduled scan {scheduled_scan.id}: {str(e)}")
    
    def _execute_scheduled_scan(self, scheduled_scan):
        """Execute a scheduled scan"""
        try:
            # Parse subnets to get IP addresses
            ip_addresses = parse_subnet_input(scheduled_scan.subnets)
            if not ip_addresses:
                logger.warning(f"No valid IP addresses found for scheduled scan {scheduled_scan.id}")
                return
            
            # Get commands
            commands = []
            if scheduled_scan.command_template_id:
                commands = scheduled_scan.command_template.commands.splitlines()
            if scheduled_scan.custom_commands:
                commands.extend(scheduled_scan.custom_commands.splitlines())
            
            # Get credentials
            username = scheduled_scan.username
            password = None
            private_key = None
            
            if scheduled_scan.auth_type == 'password' and scheduled_scan.password_encrypted:
                password = decrypt_data(scheduled_scan.password_encrypted)
            elif scheduled_scan.auth_type == 'key' and scheduled_scan.private_key_encrypted:
                private_key = decrypt_data(scheduled_scan.private_key_encrypted)
            
            # Create a new scan session
            scan_session = ScanSession(
                username=username,
                auth_type=scheduled_scan.auth_type,
                collect_server_info=scheduled_scan.collect_server_info,
                collect_detailed_info=scheduled_scan.collect_detailed_info
            )
            db.session.add(scan_session)
            db.session.commit()
            
            # Associate this scan session with the scheduled scan
            db.engine.execute(
                'INSERT INTO scheduled_scan_sessions (scheduled_scan_id, scan_session_id) VALUES (:scan_id, :session_id)',
                {'scan_id': scheduled_scan.id, 'session_id': scan_session.id}
            )
            
            # Start scan in background
            start_scan_session(
                scan_session.id,
                ip_addresses,
                username,
                password,
                private_key,
                commands,
                scheduled_scan.collect_server_info,
                scheduled_scan.collect_detailed_info,
                scheduled_scan.concurrency
            )
            
            logger.info(f"Scheduled scan {scheduled_scan.id} started with scan session {scan_session.id}")
            return scan_session.id
            
        except Exception as e:
            logger.error(f"Error starting scheduled scan {scheduled_scan.id}: {str(e)}")
            raise

# Initialize scheduler service
scheduler_service = SchedulerService()

def start_scheduler():
    """Start the scheduler service"""
    return scheduler_service.start()

def stop_scheduler():
    """Stop the scheduler service"""
    return scheduler_service.stop()

# Start scheduler when the module is imported
if not app.debug or os.environ.get('START_SCHEDULER', 'False').lower() == 'true':
    start_scheduler()