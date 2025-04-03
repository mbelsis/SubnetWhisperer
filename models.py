from app import db
from datetime import datetime, timedelta
import json
from enum import Enum

# Association table for scheduled_scans and scan_sessions
scheduled_scan_sessions = db.Table(
    'scheduled_scan_sessions',
    db.Column('scheduled_scan_id', db.Integer, db.ForeignKey('scheduled_scans.id'), primary_key=True),
    db.Column('scan_session_id', db.Integer, db.ForeignKey('scan_sessions.id'), primary_key=True)
)

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
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat(),
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
            'command_output': self.command_output,
            'server_info': json.loads(self.server_info) if self.server_info else None,
            'error_message': self.error_message,
            'execution_time': self.execution_time,
            'created_at': self.created_at.isoformat()
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
            'created_at': self.created_at.isoformat()
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
            'command_template_id': self.command_template_id,
            'custom_commands': self.custom_commands,
            'collect_server_info': self.collect_server_info,
            'collect_detailed_info': self.collect_detailed_info,
            'concurrency': self.concurrency,
            'schedule_frequency': self.schedule_frequency,
            'custom_interval_minutes': self.custom_interval_minutes,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
    
    def calculate_next_run(self):
        """Calculate the next run time based on schedule frequency"""
        if not self.is_active:
            self.next_run = None
            return
            
        base_time = self.last_run or datetime.utcnow()
        
        if self.schedule_frequency == ScheduleFrequency.HOURLY:
            self.next_run = base_time + timedelta(hours=1)
        elif self.schedule_frequency == ScheduleFrequency.DAILY:
            self.next_run = base_time + timedelta(days=1)
        elif self.schedule_frequency == ScheduleFrequency.WEEKLY:
            self.next_run = base_time + timedelta(weeks=1)
        elif self.schedule_frequency == ScheduleFrequency.MONTHLY:
            # Add 30 days for simplicity
            self.next_run = base_time + timedelta(days=30)
        elif self.schedule_frequency == ScheduleFrequency.CUSTOM:
            minutes = self.custom_interval_minutes or 60  # Default to 60 minutes
            self.next_run = base_time + timedelta(minutes=minutes)
            
        # Check if end_date is specified and if next_run is after end_date
        if self.end_date and self.next_run > self.end_date:
            self.next_run = None
            self.is_active = False
            
        return self.next_run
