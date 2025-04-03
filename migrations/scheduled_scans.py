"""
Migration script to add the scheduled_scans and related tables
"""
import os
import sqlite3
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Create migrations directory if it doesn't exist
os.makedirs('migrations', exist_ok=True)

# Get database URL from environment or use default SQLite
database_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/subnet_whisperer.db')

def migrate_database():
    """
    Add scheduled_scans and related tables
    """
    
    try:
        engine = create_engine(database_url)
        
        # Check if we're using SQLite
        if database_url.startswith('sqlite'):
            # For SQLite, check if scheduled_scans table already exists
            conn = sqlite3.connect('instance/subnet_whisperer.db')
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scheduled_scans'")
            if cursor.fetchone():
                print("Table 'scheduled_scans' already exists, skipping migration")
                conn.close()
                return
            conn.close()
            
            # Apply migration SQL directly for SQLite
            engine.execute('''
                CREATE TABLE IF NOT EXISTS scheduled_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100) NOT NULL,
                    description TEXT,
                    subnets TEXT NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    auth_type VARCHAR(20) NOT NULL DEFAULT 'password',
                    password_encrypted TEXT,
                    private_key_encrypted TEXT,
                    command_template_id INTEGER,
                    custom_commands TEXT,
                    collect_server_info BOOLEAN DEFAULT 0,
                    collect_detailed_info BOOLEAN DEFAULT 0,
                    concurrency INTEGER DEFAULT 10,
                    schedule_frequency VARCHAR(20) NOT NULL,
                    custom_interval_minutes INTEGER,
                    start_date DATETIME NOT NULL,
                    end_date DATETIME,
                    next_run DATETIME,
                    last_run DATETIME,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (command_template_id) REFERENCES command_templates (id)
                )
            ''')
            
            engine.execute('''
                CREATE TABLE IF NOT EXISTS scheduled_scan_sessions (
                    scheduled_scan_id INTEGER NOT NULL,
                    scan_session_id INTEGER NOT NULL,
                    PRIMARY KEY (scheduled_scan_id, scan_session_id),
                    FOREIGN KEY (scheduled_scan_id) REFERENCES scheduled_scans (id),
                    FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
                )
            ''')
        else:
            # For other databases (PostgreSQL, etc.), use SQLAlchemy models for migration
            Base = declarative_base()
            
            class ScheduledScan(Base):
                __tablename__ = 'scheduled_scans'
                
                id = Column(Integer, primary_key=True)
                name = Column(String(100), nullable=False)
                description = Column(Text)
                subnets = Column(Text, nullable=False)
                username = Column(String(100), nullable=False)
                auth_type = Column(String(20), nullable=False, default='password')
                password_encrypted = Column(Text)
                private_key_encrypted = Column(Text)
                command_template_id = Column(Integer, ForeignKey('command_templates.id'))
                custom_commands = Column(Text)
                collect_server_info = Column(Boolean, default=False)
                collect_detailed_info = Column(Boolean, default=False)
                concurrency = Column(Integer, default=10)
                schedule_frequency = Column(String(20), nullable=False)
                custom_interval_minutes = Column(Integer)
                start_date = Column(DateTime, nullable=False, default=datetime.utcnow)
                end_date = Column(DateTime)
                next_run = Column(DateTime)
                last_run = Column(DateTime)
                is_active = Column(Boolean, default=True)
                created_at = Column(DateTime, default=datetime.utcnow)
                updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
            
            scheduled_scan_sessions = Table(
                'scheduled_scan_sessions', 
                Base.metadata,
                Column('scheduled_scan_id', Integer, ForeignKey('scheduled_scans.id'), primary_key=True),
                Column('scan_session_id', Integer, ForeignKey('scan_sessions.id'), primary_key=True)
            )
            
            # Create tables
            Base.metadata.create_all(engine)
        
        print("Database migration for scheduled scans completed successfully")
        return True
    except Exception as e:
        print(f"Error during migration: {str(e)}")
        return False

if __name__ == "__main__":
    migrate_database()