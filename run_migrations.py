"""
Run all database migrations in sequence.
This script should be executed before starting the application
to ensure all database structures are properly set up.
"""
import logging
import importlib.util
import sys
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_migration(migration_file):
    """
    Run a specific migration file
    """
    try:
        logger.info(f"Running migration: {migration_file}")
        
        # Import the migration module
        spec = importlib.util.spec_from_file_location("migration_module", migration_file)
        if spec is None:
            logger.error(f"Failed to create spec for migration file: {migration_file}")
            return False
            
        migration_module = importlib.util.module_from_spec(spec)
        if spec.loader is None:
            logger.error(f"Failed to get loader for migration file: {migration_file}")
            return False
            
        spec.loader.exec_module(migration_module)
        
        # Run the migrate_database function
        result = migration_module.migrate_database()
        
        if result or result is None:
            logger.info(f"Migration successful: {migration_file}")
            return True
        else:
            logger.error(f"Migration failed: {migration_file}")
            return False
    
    except Exception as e:
        logger.error(f"Error running migration {migration_file}: {str(e)}")
        return False

def run_all_migrations():
    """
    Run all migration files in the migrations directory
    """
    # Get the migrations directory
    migrations_dir = Path("migrations")
    
    if not migrations_dir.exists() or not migrations_dir.is_dir():
        logger.error("Migrations directory not found")
        return False
    
    # Get all Python files in the migrations directory
    migration_files = sorted([f for f in migrations_dir.glob("*.py") 
                           if f.is_file() and f.name != "__init__.py"])
    
    if not migration_files:
        logger.info("No migration files found")
        return True
    
    # Run each migration file
    success = True
    for migration_file in migration_files:
        if not run_migration(migration_file):
            success = False
    
    return success

if __name__ == "__main__":
    success = run_all_migrations()
    sys.exit(0 if success else 1)