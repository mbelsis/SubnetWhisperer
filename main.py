import logging
import os
from app import app

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    # The schema is synced when app is imported. Debug mode (and the Werkzeug
    # debugger, which allows code execution) is opt-in via FLASK_DEBUG=true.
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes", "on")
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    if debug and host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning("FLASK_DEBUG is enabled while listening on %s; the debugger allows remote code execution", host)
    logger.info("Starting application on %s:%s (debug=%s)...", host, port, debug)
    # The reloader would start a second scheduler process; it is safe (runs are
    # claimed atomically) but noisy, so only use it in debug mode.
    app.run(host=host, port=port, debug=debug, use_reloader=debug)
