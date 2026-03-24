"""
Migration script to add the users table and create a default admin account.
"""
import os
import logging
import bcrypt
from sqlalchemy import create_engine, inspect, Column, Integer, String, Boolean, DateTime, text
from sqlalchemy.orm import declarative_base
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_database():
    """
    Add users table and create default admin account if no users exist.
    """
    try:
        # Get database URL from environment or use default SQLite database
        database_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/subnet_whisperer.db')

        # Create engine
        engine = create_engine(database_url)

        # Check if the table already exists
        insp = inspect(engine)
        if insp.has_table('users'):
            logger.info("users table already exists, checking for default admin account")
            with engine.connect() as conn:
                result = conn.execute(text("SELECT COUNT(*) FROM users"))
                count = result.scalar()
                if count == 0:
                    _create_default_admin(conn)
                    conn.commit()
                else:
                    logger.info(f"Found {count} existing user(s), skipping default account creation")
            return True

        # Create users table
        Base = declarative_base()

        class User(Base):
            __tablename__ = 'users'
            id = Column(Integer, primary_key=True)
            username = Column(String(80), unique=True, nullable=False)
            password_hash = Column(String(128), nullable=False)
            is_admin = Column(Boolean, default=False)
            created_at = Column(DateTime, default=datetime.utcnow)

        Base.metadata.create_all(engine, tables=[User.__table__])
        logger.info("Created users table")

        # Create default admin account
        with engine.connect() as conn:
            _create_default_admin(conn)
            conn.commit()

        return True

    except Exception as e:
        logger.error(f"Error running users migration: {str(e)}")
        return False


def _create_default_admin(conn):
    """Insert default admin account."""
    password_hash = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn.execute(
        text("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (:u, :p, :a, :c)"),
        {"u": "admin", "p": password_hash, "a": True, "c": datetime.utcnow()}
    )
    logger.info("Default admin account created (username: admin, password: admin)")
