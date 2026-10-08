"""
Bring the database schema up to date with models.py.

Importing the app already does this on startup; this script lets you run it
explicitly (for example from setup.sh) and get a non-zero exit code on failure.
"""
import logging
import os
import sys

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def run_all_migrations():
    """Create missing tables/columns. Returns True on success."""
    # Run relative to the project root regardless of the current directory
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    os.environ.setdefault('START_SCHEDULER', 'false')
    try:
        from app import app, db
        from migrations.schema import sync_schema
        with app.app_context():
            added = sync_schema(db)
        logger.info("Schema is up to date%s", f" (added: {', '.join(added)})" if added else "")
        return True
    except Exception:
        logger.exception("Database migration failed")
        return False


if __name__ == "__main__":
    sys.exit(0 if run_all_migrations() else 1)
