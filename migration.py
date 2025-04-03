"""
Migration script to add the collect_detailed_info column to scan_sessions table
"""
import sqlite3
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_database():
    """
    Add collect_detailed_info column to scan_sessions table
    """
    db_path = os.path.join('instance', 'subnet_whisperer.db')
    
    if not os.path.exists(db_path):
        logger.error(f"Database file not found at {db_path}")
        return False
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if the column already exists
        cursor.execute("PRAGMA table_info(scan_sessions)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'collect_detailed_info' not in column_names:
            logger.info("Adding collect_detailed_info column to scan_sessions table")
            cursor.execute("ALTER TABLE scan_sessions ADD COLUMN collect_detailed_info BOOLEAN DEFAULT 0")
            conn.commit()
            logger.info("Migration completed successfully")
        else:
            logger.info("Column collect_detailed_info already exists in scan_sessions table")
        
        conn.close()
        return True
    
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return False
    except Exception as e:
        logger.error(f"Error: {e}")
        return False

if __name__ == "__main__":
    migrate_database()