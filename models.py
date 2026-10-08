from app import db
from datetime import datetime, timedelta
import json
from enum import Enum
from flask_login import UserMixin
import bcrypt
import calendar


def _iso(dt):
    """Serialize a naive UTC datetime as an ISO 8601 string with a Z suffix."""
    return dt.isoformat() + 'Z' if dt else None


def _add_months(dt, months):
    """Add calendar months to a datetime, clamping the day to the month's length."""
    month_index = dt.month - 1 + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


class User(UserMixin, db.Model):
    """Model for application user accounts"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def session_token(self):
        """Short fingerprint of the password hash; changes whenever the password changes."""
        return self.password_hash[-16:]

    def get_id(self):
        # Binding the login session to the password hash invalidates existing
        # sessions when the password is changed or reset.
        return f"{self.id}:{self.session_token()}"

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'created_at': _iso(self.created_at),
        }

# Association table for scheduled_scans and scan_sessions
scheduled_scan_sessions = db.Table(
    'scheduled_scan_sessions',
    db.Column('scheduled_scan_id', db.Integer, db.ForeignKey('scheduled_scans.id'), primary_key=True),
    db.Column('scan_session_id', db.Integer, db.ForeignKey('scan_sessions.id'), primary_key=True)
)

# Association table for scan_sessions and credential_sets
scan_session_credentials = db.Table(
    'scan_session_credentials',
    db.Column('scan_session_id', db.Integer, db.ForeignKey('scan_sessions.id'), primary_key=True),
    db.Column('credential_set_id', db.Integer, db.ForeignKey('credential_sets.id'), primary_key=True)
)

class CredentialSet(db.Model):
    """Model for storing multiple credential sets for SSH authentication"""
    __tablename__ = 'credential_sets'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    auth_type = db.Column(db.String(20), nullable=False, default='password')  # 'password' or 'key'
    password_encrypted = db.Column(db.Text)
    private_key_encrypted = db.Column(db.Text)
    sudo_password_encrypted = db.Column(db.Text)  # For sudo commands
    description = db.Column(db.String(255))  # Optional description
    priority = db.Column(db.Integer, default=0)  # Priority order for trying credentials
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan_sessions = db.relationship('ScanSession', secondary='scan_session_credentials',
                                  backref=db.backref('credential_sets', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'auth_type': self.auth_type,
            'has_password': bool(self.password_encrypted),
            'has_private_key': bool(self.private_key_encrypted),
            'has_sudo_password': bool(self.sudo_password_encrypted),
            'description': self.description,
            'priority': self.priority,
            'created_at': _iso(self.created_at),
            'updated_at': _iso(self.updated_at)
        }
    
def _load_json(value):
    """Parse a stored JSON column, returning the raw text if it is not valid JSON."""
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value

class ScheduleFrequency(str, Enum):
    HOURLY = 'hourly'
    DAILY = 'daily'
    WEEKLY = 'weekly'
    MONTHLY = 'monthly'
    CUSTOM = 'custom'  # For custom interval in minutes

class ScanSession(db.Model):
    __tablename__ = 'scan_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    auth_type = db.Column(db.String(20), nullable=False, default='password')  # 'password' or 'key'
    collect_server_info = db.Column(db.Boolean, default=False)
    collect_detailed_info = db.Column(db.Boolean, default=False)  # For detailed server profiling
    total_ips = db.Column(db.Integer, default=0)  # Expected number of IPs to scan
    status = db.Column(db.String(20), default='running')  # running, completed, failed
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    results = db.relationship('ScanResult', backref='session', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'auth_type': self.auth_type,
            'collect_server_info': self.collect_server_info,
            'collect_detailed_info': self.collect_detailed_info,
            'status': self.status,
            'started_at': _iso(self.started_at),
            'completed_at': _iso(self.completed_at),
            'created_at': _iso(self.created_at),
            'success_count': sum(1 for r in self.results if r.status_code == 'success'),
            'failed_count': sum(1 for r in self.results if r.status_code == 'failed'),
            'total_count': len(self.results)
        }

class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_session_id = db.Column(db.Integer, db.ForeignKey('scan_sessions.id'), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    status_code = db.Column(db.String(20), nullable=False)  # success, failed, pending
    ssh_status = db.Column(db.Boolean, default=False)
    sudo_status = db.Column(db.Boolean, default=False)
    command_status = db.Column(db.Boolean, default=False)
    command_output = db.Column(db.Text)
    server_info = db.Column(db.Text)
    error_message = db.Column(db.Text)
    execution_time = db.Column(db.Float)  # in seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_session_id': self.scan_session_id,
            'ip_address': self.ip_address,
            'status_code': self.status_code,
            'ssh_status': self.ssh_status,
            'sudo_status': self.sudo_status,
            'command_status': self.command_status,
            'command_output': _load_json(self.command_output),
            'server_info': _load_json(self.server_info),
            'error_message': self.error_message,
            'execution_time': self.execution_time,
            'created_at': _iso(self.created_at)
        }

class CommandTemplate(db.Model):
    __tablename__ = 'command_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    commands = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'commands': self.commands,
            'created_at': _iso(self.created_at)
        }
        
class ScheduledScan(db.Model):
    __tablename__ = 'scheduled_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    # Scan configuration
    subnets = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    auth_type = db.Column(db.String(20), nullable=False, default='password')
    # Note: Password/key are stored encrypted or are entered at runtime
    password_encrypted = db.Column(db.Text)
    private_key_encrypted = db.Column(db.Text)
    sudo_password_encrypted = db.Column(db.Text)
    port = db.Column(db.Integer, default=22)
    # Optional saved credential set; when set it overrides username/password/key above
    credential_set_id = db.Column(db.Integer, db.ForeignKey('credential_sets.id'))
    
    # Command options
    command_template_id = db.Column(db.Integer, db.ForeignKey('command_templates.id'))
    custom_commands = db.Column(db.Text)
    collect_server_info = db.Column(db.Boolean, default=False)
    collect_detailed_info = db.Column(db.Boolean, default=False)
    concurrency = db.Column(db.Integer, default=10)
    
    # Schedule configuration
    schedule_frequency = db.Column(db.String(20), nullable=False)
    custom_interval_minutes = db.Column(db.Integer)  # For custom frequency
    start_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)  # Optional end date
    next_run = db.Column(db.DateTime)
    last_run = db.Column(db.DateTime)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    command_template = db.relationship('CommandTemplate', backref='scheduled_scans')
    credential_set = db.relationship('CredentialSet', backref='scheduled_scans')
    scan_sessions = db.relationship('ScanSession', secondary='scheduled_scan_sessions', 
                                   backref='scheduled_scan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'subnets': self.subnets,
            'username': self.username,
            'auth_type': self.auth_type,
            'has_password': bool(self.password_encrypted),
            'has_private_key': bool(self.private_key_encrypted),
            'has_sudo_password': bool(self.sudo_password_encrypted),
            'port': self.port,
            'credential_set_id': self.credential_set_id,
            'command_template_id': self.command_template_id,
            'custom_commands': self.custom_commands,
            'collect_server_info': self.collect_server_info,
            'collect_detailed_info': self.collect_detailed_info,
            'concurrency': self.concurrency,
            'schedule_frequency': self.schedule_frequency,
            'custom_interval_minutes': self.custom_interval_minutes,
            'start_date': _iso(self.start_date),
            'end_date': _iso(self.end_date),
            'next_run': _iso(self.next_run),
            'last_run': _iso(self.last_run),
            'is_active': self.is_active,
            'created_at': _iso(self.created_at),
            'updated_at': _iso(self.updated_at),
        }
    
    def _advance(self, base_time):
        """Return base_time moved forward by one schedule interval."""
        if self.schedule_frequency == ScheduleFrequency.HOURLY:
            return base_time + timedelta(hours=1)
        if self.schedule_frequency == ScheduleFrequency.DAILY:
            return base_time + timedelta(days=1)
        if self.schedule_frequency == ScheduleFrequency.WEEKLY:
            return base_time + timedelta(weeks=1)
        if self.schedule_frequency == ScheduleFrequency.MONTHLY:
            return _add_months(base_time, 1)
        minutes = max(self.custom_interval_minutes or 60, 1)  # CUSTOM, default 60 minutes
        return base_time + timedelta(minutes=minutes)

    def calculate_next_run(self, now=None):
        """Calculate the next run time (UTC) based on schedule frequency.

        The first run happens at start_date. Later runs are one interval after
        the previous run; runs missed while the app was down are skipped rather
        than replayed back-to-back.
        """
        if not self.is_active:
            self.next_run = None
            return None

        now = now or datetime.utcnow()
        start = self.start_date or now

        # A schedule whose end date has passed can never run again
        if self.end_date and self.end_date <= now:
            self.next_run = None
            self.is_active = False
            return None

        if self.last_run is None:
            next_run = start
        else:
            next_run = self._advance(max(self.last_run, start))
            while next_run <= now:
                next_run = self._advance(next_run)

        # Deactivate once the schedule has run past its end date
        if self.end_date and next_run > self.end_date:
            self.next_run = None
            self.is_active = False
            return None

        self.next_run = next_run
        return next_run
