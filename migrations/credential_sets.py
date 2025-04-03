"""
Migration script to add the credential_sets table and relation tables
"""
import os
import sys
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Table, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_database():
    """
    Add credential_sets and related tables
    """
    try:
        # Get database URL from environment or use default SQLite database
        database_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/subnet_whisperer.db')
        
        # Create engine
        engine = create_engine(database_url)
        
        # Create session
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Check if the tables already exist
        if engine.dialect.has_table(engine, 'credential_sets'):
            logger.info("credential_sets table already exists, skipping migration")
            return
        
        # Create Base class
        Base = declarative_base()
        
        # Define models for migration
        
        class CredentialSet(Base):
            __tablename__ = 'credential_sets'
            
            id = Column(Integer, primary_key=True)
            username = Column(String(100), nullable=False)
            auth_type = Column(String(20), nullable=False, default='password')
            password_encrypted = Column(Text)
            private_key_encrypted = Column(Text)
            sudo_password_encrypted = Column(Text)
            description = Column(String(255))
            priority = Column(Integer, default=0)
            created_at = Column(DateTime, default=datetime.utcnow)
            updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Create association table
        scan_session_credentials = Table(
            'scan_session_credentials',
            Base.metadata,
            Column('scan_session_id', Integer, ForeignKey('scan_sessions.id'), primary_key=True),
            Column('credential_set_id', Integer, ForeignKey('credential_sets.id'), primary_key=True)
        )
        
        # Create the tables
        Base.metadata.create_all(engine)
        
        # Commit the session
        session.commit()
        
        logger.info("Database migration for credential sets completed successfully")
        return True
    
    except Exception as e:
        logger.error(f"Error during migration: {str(e)}")
        return False

if __name__ == "__main__":
    migrate_database()