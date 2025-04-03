import logging
import sys
from run_migrations import run_all_migrations
from app import app

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    # Run migrations before starting the app
    logger.info("Running database migrations...")
    if not run_all_migrations():
        logger.error("Failed to run migrations. Exiting.")
        sys.exit(1)
    
    # Start the application
    logger.info("Starting application...")
    app.run(host="0.0.0.0", port=5000, debug=True)
