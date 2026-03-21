"""
Migration script to add the scheduled_scans and related tables
"""
import os
import logging
from datetime import datetime
from sqlalchemy import create_engine, inspect, text, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.orm import declarative_base

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

        # Check if tables already exist
        insp = inspect(engine)
        if insp.has_table('scheduled_scans'):
            logger.info("Table 'scheduled_scans' already exists, skipping migration")
            return True

        # Use SQLAlchemy models for migration (works for all databases)
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

        logger.info("Database migration for scheduled scans completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error during migration: {str(e)}")
        return False

if __name__ == "__main__":
    migrate_database()