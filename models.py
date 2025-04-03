from app import db
from datetime import datetime
import json

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
