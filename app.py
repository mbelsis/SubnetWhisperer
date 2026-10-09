import os
import time
import logging
import secrets
import threading
from collections import defaultdict, deque
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort, g,
                   make_response)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import DeclarativeBase

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
MIN_PASSWORD_LENGTH = 8


def _env_flag(name, default=False):
    """Read a boolean environment variable."""
    value = os.environ.get(name)
    if value is None or value == '':
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


# Configure logging
logging.basicConfig(level=logging.DEBUG if _env_flag('FLASK_DEBUG') else logging.INFO)
logger = logging.getLogger(__name__)

# Setup base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)


def _write_private_file(path, content):
    """Create a file readable only by the owner (fails if it already exists)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content)


def _read_secret_file(path):
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def _get_or_create_secret():
    """Get session secret from env, or generate and persist one to a file.

    Safe when several processes start at once: the file is created with
    O_EXCL, and a process that loses the race uses the winner's secret.
    """
    secret = os.environ.get("SESSION_SECRET")
    if secret:
        return secret
    secret_file = os.path.join(INSTANCE_DIR, '.secret_key')
    for attempt in range(20):
        existing = _read_secret_file(secret_file)
        if existing:
            return existing
        if existing == '':
            # Another process may be writing it right now; a file that stays
            # empty was left by an interrupted write and is replaced.
            if attempt < 10:
                time.sleep(0.1)
                continue
            try:
                os.remove(secret_file)
            except FileNotFoundError:
                pass
        try:
            secret = secrets.token_hex(32)
            _write_private_file(secret_file, secret)
            return secret
        except FileExistsError:
            continue  # another process created it first; use theirs
    raise RuntimeError(f"Could not read or create {secret_file}; set SESSION_SECRET")


def _database_uri():
    """Return the database URI, resolving relative SQLite paths against the project root."""
    uri = os.environ.get("DATABASE_URL") or "sqlite:///instance/subnet_whisperer.db"
    prefix = "sqlite:///"
    if uri.startswith(prefix) and not uri.startswith(prefix + "/") and ":memory:" not in uri:
        uri = prefix + os.path.join(BASE_DIR, uri[len(prefix):])
    return uri


app.secret_key = _get_or_create_secret()

# Behind a reverse proxy, trust this many X-Forwarded-* hops so request.remote_addr
# (used for login throttling and the audit log) is the real client address.
_proxy_hops = int(os.environ.get("TRUST_PROXY_HOPS", "0") or 0)
if _proxy_hops > 0:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_hops, x_proto=_proxy_hops, x_host=_proxy_hops)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = _database_uri()
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session cookie hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = _env_flag("SESSION_COOKIE_SECURE")
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = _env_flag("SESSION_COOKIE_SECURE")

# CSRF tokens stay valid for the lifetime of the session
app.config["WTF_CSRF_TIME_LIMIT"] = None

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize the database with the app
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'


def _create_initial_admin():
    """Create the first admin account with a random (or ADMIN_PASSWORD) password."""
    from models import User
    password = os.environ.get('ADMIN_PASSWORD')
    generated = not password
    if generated:
        password = secrets.token_urlsafe(12)
    admin = User(username='admin', is_admin=True, must_change_password=True)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    if generated:
        password_file = os.path.join(INSTANCE_DIR, 'initial_admin_password')
        try:
            if os.path.exists(password_file):
                os.remove(password_file)
            _write_private_file(password_file, password + '\n')
        except OSError as e:
            logger.error(f"Could not write {password_file}: {e}")
        logger.warning(
            "Created initial admin account 'admin' with generated password: %s "
            "(also saved to instance/initial_admin_password). "
            "You will be asked to change it at first login.", password)
    else:
        logger.info("Created initial admin account 'admin' from ADMIN_PASSWORD; "
                    "a password change is required at first login.")


audit_logger = logging.getLogger('audit')
_CURRENT_USER = object()


def audit(action, target=None, details=None, outcome='success', user=_CURRENT_USER):
    """Record a security-relevant event in the audit_log table and the 'audit' logger.

    Call it after the change itself has been committed: it commits its own row.
    Never pass secrets in details. user=None records a system action (scheduler).
    """
    from models import AuditLog
    if user is _CURRENT_USER:
        user = current_user if current_user and current_user.is_authenticated else None
    user_id = getattr(user, 'id', None)
    username = getattr(user, 'username', None)
    try:
        source_ip = request.remote_addr
    except RuntimeError:  # outside a request (scheduler)
        source_ip = None
    audit_logger.info("action=%s outcome=%s user=%s ip=%s target=%s details=%s",
                      action, outcome, username or '-', source_ip or '-', target or '-', details or '')
    try:
        db.session.add(AuditLog(user_id=user_id, username=username, action=action,
                                target=(target or '')[:255] or None, details=details,
                                source_ip=source_ip, outcome=outcome))
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Could not write audit log entry for %s", action)


# Import routes and models after initializing app and db
with app.app_context():
    from models import User, ScanResult, CommandTemplate, ScanSession, ScheduledScan, CredentialSet, AuditLog
    import ssh_utils
    import subnet_utils
    from forms import ScanForm, CommandTemplateForm, ScheduledScanForm
    from migrations.schema import sync_schema

    # Create missing tables and add columns introduced by newer versions
    sync_schema(db)

    # Create the initial admin account if no users exist
    if User.query.count() == 0:
        try:
            _create_initial_admin()
        except Exception:
            db.session.rollback()
            logger.info("Initial admin account already exists (created by another process)")

    # Scans left 'running' by a previous process died with it
    if _env_flag('RECOVER_INTERRUPTED_SCANS', default=True):
        try:
            ssh_utils.recover_interrupted_scans()
        except Exception:
            db.session.rollback()
            logger.exception("Could not mark interrupted scans")


# ---------------------------------------------------------------------------
# Login throttling (in-memory; the app runs as a single process)
# ---------------------------------------------------------------------------

class LoginThrottle:
    """Lock out a (username, client IP) pair after too many failures, and a client IP
    after many more. Locking per pair means an attacker cannot lock the real admin
    out from a different address."""

    def __init__(self, max_failures, ip_max_failures, window_seconds):
        self.max_failures = max_failures
        self.ip_max_failures = ip_max_failures
        self.window = window_seconds
        self._failures = defaultdict(deque)
        self._lock = threading.Lock()

    def _recent(self, key, now):
        q = self._failures.get(key)
        if not q:
            return 0
        while q and q[0] <= now - self.window:
            q.popleft()
        if not q:
            self._failures.pop(key, None)
            return 0
        return len(q)

    def retry_after(self, username, ip):
        """Seconds until a login may be attempted again (0 = allowed now)."""
        now = time.monotonic()
        with self._lock:
            waits = []
            for key, limit in (((username.lower(), ip), self.max_failures), (('*', ip), self.ip_max_failures)):
                if self._recent(key, now) >= limit:
                    waits.append(self._failures[key][0] + self.window - now)
            return int(max(waits)) + 1 if waits else 0

    def failure(self, username, ip):
        now = time.monotonic()
        with self._lock:
            for key in ((username.lower(), ip), ('*', ip)):
                self._failures[key].append(now)
            # Bound memory under a spray of random usernames
            if len(self._failures) > 10000:
                for key in list(self._failures):
                    self._recent(key, now)

    def success(self, username, ip):
        with self._lock:
            self._failures.pop((username.lower(), ip), None)


login_throttle = LoginThrottle(
    max_failures=int(os.environ.get('LOGIN_MAX_FAILURES', '5') or 5),
    ip_max_failures=int(os.environ.get('LOGIN_IP_MAX_FAILURES', '20') or 20),
    window_seconds=60 * int(os.environ.get('LOGIN_LOCKOUT_MINUTES', '15') or 15),
)

# Compared against when the username does not exist, so the response time does
# not reveal which usernames are valid.
import bcrypt as _bcrypt  # noqa: E402
_DUMMY_PASSWORD_HASH = _bcrypt.hashpw(b'not-a-real-password', _bcrypt.gensalt())


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

_CDN_SCRIPTS = "https://cdn.jsdelivr.net https://code.jquery.com https://cdn.datatables.net"
_CDN_STYLES = "https://cdn.replit.com https://cdnjs.cloudflare.com https://cdn.datatables.net"


@app.before_request
def _set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def _inject_csp_nonce():
    return {'csp_nonce': lambda: getattr(g, 'csp_nonce', '')}


@app.after_request
def _security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers.setdefault('Content-Security-Policy', (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' {_CDN_SCRIPTS}; "
        # Inline style attributes are used by the templates and DataTables
        f"style-src 'self' 'unsafe-inline' {_CDN_STYLES}; "
        "font-src 'self' data: https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://cdn.datatables.net; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"))
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    # Scan results and credentials pages must not be kept in shared caches
    if request.endpoint != 'static':
        response.headers.setdefault('Cache-Control', 'no-store')
    return response


def _wants_json():
    """True for fetch/XHR API calls, which should get JSON errors instead of redirects."""
    if request.is_json or request.path.startswith('/api/') or request.method in ('PUT', 'DELETE'):
        return True
    if request.headers.get('X-CSRFToken') or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return best == 'application/json' and request.accept_mimetypes[best] > request.accept_mimetypes['text/html']


def admin_required(view):
    """Allow only admins; JSON callers get 403, page callers are redirected."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.is_admin:
            if _wants_json():
                return jsonify({"error": "Admin privileges required"}), 403
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('index'))
        return view(*args, **kwargs)
    return wrapper


@app.before_request
def enforce_password_change():
    """Force users flagged with must_change_password to change it before anything else."""
    if (current_user.is_authenticated and getattr(current_user, 'must_change_password', False)
            and request.endpoint not in ('change_password', 'logout', 'static')):
        if _wants_json():
            return jsonify({"error": "Password change required"}), 403
        flash('Please change your password before continuing.', 'warning')
        return redirect(url_for('change_password'))


def _is_safe_redirect(target):
    """Allow only same-site relative paths (no scheme, host, or backslashes)."""
    from urllib.parse import urlparse
    if not target or '\\' in target or not target.startswith('/') or target.startswith('//'):
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc


INITIAL_ADMIN_PASSWORD_FILE = os.path.join(INSTANCE_DIR, 'initial_admin_password')


def _remove_initial_admin_password_file():
    """Delete the generated first-run admin password once an admin has set a new password."""
    if current_user.is_admin and os.path.exists(INITIAL_ADMIN_PASSWORD_FILE):
        try:
            os.remove(INITIAL_ADMIN_PASSWORD_FILE)
            logger.info("Removed %s after the admin password was changed", INITIAL_ADMIN_PASSWORD_FILE)
        except OSError as e:
            logger.error("Could not remove %s: %s", INITIAL_ADMIN_PASSWORD_FILE, e)


def _validate_new_password(password):
    """Return an error message if the password does not meet the policy, else None."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f'Password must be at least {MIN_PASSWORD_LENGTH} characters.'
    return None


def _json_error(message, status=400):
    return jsonify({"error": message}), status


@login_manager.user_loader
def load_user(user_id):
    from models import User
    user_pk, _, token = str(user_id).partition(':')
    try:
        user = db.session.get(User, int(user_pk))
    except ValueError:
        return None
    if user is None or not secrets.compare_digest(token, user.session_token()):
        return None
    return user

# Auth Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    from models import User
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = request.remote_addr or 'unknown'
        wait = login_throttle.retry_after(username, client_ip)
        if wait:
            audit('auth.login', f"user:{username}"[:255], outcome='denied', user=None,
                  details='locked out after repeated failures')
            flash(f'Too many failed login attempts. Try again in {(wait + 59) // 60} minute(s).', 'danger')
            return render_template('login.html'), 429
        user = User.query.filter_by(username=username).first()
        if user is None:
            _bcrypt.checkpw(password.encode('utf-8'), _DUMMY_PASSWORD_HASH)
        if user and user.check_password(password):
            login_throttle.success(username, client_ip)
            login_user(user)
            audit('auth.login', f"user:{user.username}")
            if user.must_change_password:
                return redirect(url_for('change_password'))
            next_page = request.args.get('next')
            # Only allow relative redirects to prevent open redirect attacks
            if not _is_safe_redirect(next_page):
                next_page = None
            return redirect(next_page or url_for('index'))
        login_throttle.failure(username, client_ip)
        logger.warning("Failed login attempt for username %r from %s", username, request.remote_addr)
        audit('auth.login', f"user:{username}"[:255], outcome='failure', user=None)
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    audit('auth.logout', f"user:{current_user.username}")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/users')
@admin_required
def user_management():
    from models import User
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users)

@app.route('/users/create', methods=['POST'])
@admin_required
def create_user():
    from models import User
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    is_admin = request.form.get('is_admin') == 'on'
    if not username or not password:
        flash('Username and password are required.', 'danger')
        return redirect(url_for('user_management'))
    if len(username) > 80 or not all(c.isalnum() or c in '._-' for c in username):
        flash('Username may contain only letters, digits, ".", "_" and "-" (max 80).', 'danger')
        return redirect(url_for('user_management'))
    password_error = _validate_new_password(password)
    if password_error:
        flash(password_error, 'danger')
        return redirect(url_for('user_management'))
    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'danger')
        return redirect(url_for('user_management'))
    user = User(username=username, is_admin=is_admin, must_change_password=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    audit('user.create', f"user:{user.id}", details=f"username={username} admin={is_admin}")
    flash(f'User "{username}" created successfully. They must change the password at first login.', 'success')
    return redirect(url_for('user_management'))

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    from models import User, ScanSession, ScheduledScan
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('user_management'))
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash('You cannot delete the last admin account.', 'danger')
        return redirect(url_for('user_management'))
    username = user.username
    # Keep the user's scans and schedules; they become visible to admins only
    ScanSession.query.filter_by(owner_id=user.id).update({ScanSession.owner_id: None})
    ScheduledScan.query.filter_by(owner_id=user.id).update({ScheduledScan.owner_id: None})
    db.session.delete(user)
    db.session.commit()
    audit('user.delete', f"user:{user_id}", details=f"username={username}")
    flash(f'User "{username}" deleted.', 'success')
    return redirect(url_for('user_management'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        password_error = _validate_new_password(new_password)
        if not current_user.check_password(current_password):
            audit('user.password_change', f"user:{current_user.id}", outcome='failure',
                  details='current password incorrect')
            flash('Current password is incorrect.', 'danger')
        elif password_error:
            flash(password_error, 'danger')
        elif new_password == current_password:
            flash('New password must be different from the current password.', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
        else:
            user = current_user._get_current_object()
            user.set_password(new_password)
            user.must_change_password = False
            db.session.commit()
            _remove_initial_admin_password_file()
            # The session token changed with the password; refresh this session.
            # Pass the real User, not the current_user proxy (which would then refer to itself).
            login_user(user)
            audit('user.password_change', f"user:{user.id}")
            flash('Password changed successfully.', 'success')
            return redirect(url_for('index'))
    return render_template('change_password.html',
                           forced=bool(getattr(current_user, 'must_change_password', False)),
                           min_length=MIN_PASSWORD_LENGTH)

@app.route('/users/<int:user_id>/reset_password', methods=['POST'])
@admin_required
def reset_user_password(user_id):
    from models import User
    user = db.get_or_404(User, user_id)
    new_password = request.form.get('new_password', '')
    password_error = _validate_new_password(new_password)
    if password_error:
        flash(password_error, 'danger')
        return redirect(url_for('user_management'))
    user.set_password(new_password)
    # Existing sessions of that user are invalidated by the new password hash
    user.must_change_password = user.id != current_user.id
    db.session.commit()
    if user.id == current_user.id:
        login_user(user)
    audit('user.password_reset', f"user:{user.id}", details=f"username={user.username}")
    flash(f'Password reset for user "{user.username}".', 'success')
    return redirect(url_for('user_management'))

def _visible_scans():
    """ScanSession query limited to what the current user may see (admins: everything)."""
    from models import ScanSession
    query = ScanSession.query
    if not current_user.is_admin:
        query = query.filter(ScanSession.owner_id == current_user.id)
    return query


def _get_visible_scan_or_404(scan_id):
    """Load a scan the current user may see. Others get 404 so IDs cannot be probed."""
    from models import ScanSession
    scan_session = db.session.get(ScanSession, scan_id)
    if scan_session is None or (not current_user.is_admin and scan_session.owner_id != current_user.id):
        if _wants_json():
            abort(make_response(jsonify({"error": "Scan not found"}), 404))
        abort(404)
    return scan_session


def _command_policy_error(commands):
    """In allowlist mode, return an error for commands that are not in a template, else None."""
    from security_utils import is_allowlist_mode
    from models import approved_template_commands
    if not commands or not is_allowlist_mode():
        return None
    approved = approved_template_commands()
    rejected = [c for c in commands if c.strip() not in approved]
    if not rejected:
        return None
    from security_utils import mask_sensitive_data
    sample = ', '.join(repr(mask_sensitive_data(c))[:80] for c in rejected[:3])
    return (f"{len(rejected)} command(s) are not in an approved command template "
            f"(COMMAND_SANITIZATION=allowlist): {sample}")


def _scope_error(ip_addresses):
    """Return an error if any address is outside SCAN_ALLOWED_SUBNETS, else None."""
    from subnet_utils import out_of_scope
    outside = out_of_scope(ip_addresses)
    if not outside:
        return None
    return (f"{len(outside)} address(es) are outside the authorised scan scope "
            f"(SCAN_ALLOWED_SUBNETS), e.g. {', '.join(outside[:5])}")


# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET'])
@login_required
def scan():
    from forms import ScanForm
    from models import CommandTemplate, CredentialSet

    form = ScanForm()
    templates = CommandTemplate.query.all()
    # Only admins may use saved credential sets
    credential_sets = (CredentialSet.query.order_by(CredentialSet.priority.desc()).all()
                       if current_user.is_admin else [])

    # Populate form choices
    form.command_template.choices = [(t.id, t.name) for t in templates]

    from security_utils import is_allowlist_mode
    from ssh_utils import MAX_CONCURRENCY
    return render_template('scan.html', form=form, templates=templates, credential_sets=credential_sets,
                           allowlist_mode=is_allowlist_mode(), max_concurrency=MAX_CONCURRENCY)


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def _as_int(value, default, minimum, maximum, name):
    """Parse an int from user input and check its range; raises ValueError with a readable message."""
    if value is None or value == '':
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number")
    if number < minimum or number > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return number


def _split_commands(text):
    """Split a multi-line command string into non-empty, stripped commands."""
    if not text or not isinstance(text, str):
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    from subnet_utils import parse_subnet_input
    from ssh_utils import start_scan_session, MAX_CONCURRENCY
    from models import ScanSession, CommandTemplate, CredentialSet, approved_template_commands
    from security_utils import is_allowlist_mode

    if request.is_json:
        data = request.get_json(silent=True)
        if not data:
            return _json_error("No data provided")
        get = data.get
        username_key, auth_key, password_key, key_key = 'username', 'auth_type', 'password', 'private_key'
        passphrase_key = 'private_key_passphrase'
        template_key, commands_key, sudo_key = 'template_id', 'custom_commands', 'sudo_password'
        info_key, detailed_key, credset_key = 'collect_server_info', 'collect_detailed_info', 'credential_set_id'
    else:
        get = request.form.get
        username_key, auth_key, password_key, key_key = 'username', 'authType', 'password', 'privateKey'
        passphrase_key = 'privateKeyPassphrase'
        template_key, commands_key, sudo_key = 'commandTemplate', 'customCommands', 'sudoPassword'
        info_key, detailed_key, credset_key = 'collectServerInfo', 'collectDetailedInfo', 'credentialSet'

    subnets = get('subnets', '') or ''
    template_id = get(template_key)
    custom_commands = get(commands_key, '') or ''
    collect_server_info = _as_bool(get(info_key))
    collect_detailed_info = _as_bool(get(detailed_key))
    sudo_password = get(sudo_key) or None
    use_credential_sets = _as_bool(get('use_credential_sets'))
    multiple_credentials = _as_bool(get('multiple_credentials'))
    credential_set_id = get(credset_key)

    try:
        concurrency = _as_int(get('concurrency'), 10, 1, MAX_CONCURRENCY, 'Concurrency')
        port = _as_int(get('port'), 22, 1, 65535, 'Port')
    except ValueError as e:
        return _json_error(str(e))

    # Validate subnets early
    if not subnets or not isinstance(subnets, str):
        return _json_error("No subnets provided")

    # Authentication info initialization
    username = None
    auth_type = None
    password = None
    private_key = None
    private_key_passphrase = None
    credential_set_ids = None

    # Handle credential sets logic
    if use_credential_sets:
        if not current_user.is_admin:
            return _json_error("Only admins can scan with saved credential sets", 403)
        if not credential_set_id and not multiple_credentials:
            return _json_error("No credential set selected")

        if multiple_credentials:
            # Get all credential sets in priority order
            credential_sets = CredentialSet.query.order_by(CredentialSet.priority.desc()).all()
            if not credential_sets:
                return _json_error("No credential sets found")
        else:
            try:
                credential_set = db.session.get(CredentialSet, int(credential_set_id))
            except (TypeError, ValueError):
                credential_set = None
            if not credential_set:
                return _json_error("Invalid credential set selected")
            credential_sets = [credential_set]

        # Use first credential set for scan session record; workers re-load by id
        username = credential_sets[0].username
        auth_type = credential_sets[0].auth_type
        credential_set_ids = [c.id for c in credential_sets]
    else:
        username = (get(username_key, '') or '').strip()
        auth_type = get(auth_key, 'password') or 'password'
        if auth_type not in ('password', 'key'):
            return _json_error("auth_type must be 'password' or 'key'")
        password = (get(password_key, '') or None) if auth_type == 'password' else None
        private_key = (get(key_key, '') or None) if auth_type == 'key' else None
        private_key_passphrase = (get(passphrase_key, '') or None) if auth_type == 'key' else None

        # Validate manual credentials
        if not username:
            return _json_error("Username is required")
        if auth_type == 'password' and not password:
            return _json_error("Password is required")
        if auth_type == 'key' and not private_key:
            return _json_error("Private key is required")

    # Parse subnets
    errors = []
    try:
        ip_addresses = parse_subnet_input(subnets, errors=errors)
    except ValueError as e:
        return _json_error(str(e))
    except Exception:
        logger.exception("Error parsing subnets")
        return _json_error("Could not parse the subnet input")
    if not ip_addresses:
        detail = f": {'; '.join(errors[:5])}" if errors else ""
        return _json_error(f"No valid IP addresses found{detail}")
    scope_error = _scope_error(ip_addresses)
    if scope_error:
        audit('scan.start', None, outcome='denied', details=scope_error)
        return _json_error(scope_error, 403)

    # Get commands
    commands = []
    if template_id not in (None, ''):
        try:
            template = db.session.get(CommandTemplate, int(template_id))
        except (TypeError, ValueError):
            template = None
        if template is None:
            return _json_error("Selected command template does not exist")
        commands = _split_commands(template.commands)
    commands.extend(_split_commands(custom_commands))
    policy_error = _command_policy_error(commands)
    if policy_error:
        audit('scan.start', None, outcome='denied', details=policy_error)
        return _json_error(policy_error, 403)

    # Create a new scan session
    scan_session = ScanSession(
        owner_id=current_user.id,
        username=username,
        auth_type=auth_type,
        collect_server_info=collect_server_info,
        collect_detailed_info=collect_detailed_info,
        total_ips=len(ip_addresses)
    )
    db.session.add(scan_session)
    db.session.commit()
    scan_id = scan_session.id

    # Store session ID in session
    session['current_scan_id'] = scan_id

    # Start scan in background
    try:
        start_scan_session(
            scan_session_id=scan_id,
            ip_addresses=ip_addresses,
            username=username,
            password=password,
            private_key=private_key,
            commands=commands,
            collect_server_info=collect_server_info,
            collect_detailed_info=collect_detailed_info,
            sudo_password=sudo_password,
            credential_set_ids=credential_set_ids,
            concurrency=concurrency,
            port=port,
            private_key_passphrase=private_key_passphrase,
            allowed_commands=approved_template_commands() if is_allowlist_mode() else None
        )
    except Exception:
        logger.exception("Failed to start scan %s", scan_id)
        scan_session.status = 'failed'
        db.session.commit()
        return _json_error("Failed to start the scan", 500)

    audit('scan.start', f"scan:{scan_id}", details=(
        f"{len(ip_addresses)} host(s), port {port}, {len(commands)} command(s), "
        f"auth={'credential_sets:' + ','.join(map(str, credential_set_ids)) if credential_set_ids else auth_type}, "
        f"ssh_user={username}, sudo_password={'yes' if sudo_password else 'no'}"))

    message = f"Scan started with {len(ip_addresses)} IP addresses"
    if errors:
        message += f" ({len(errors)} invalid entries skipped)"
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "message": message,
        "warnings": errors[:20],
    })

@app.route('/validate_subnets', methods=['POST'])
@login_required
def validate_subnets():
    from subnet_utils import parse_subnet_input, MAX_SCAN_IPS

    data = request.get_json(silent=True) or {}
    subnets = data.get('subnets') or ''
    errors = []
    try:
        ip_addresses = parse_subnet_input(subnets, errors=errors) if isinstance(subnets, str) else []
    except ValueError as e:
        return jsonify({"valid": False, "count": 0, "sample": [], "errors": [str(e)], "limit": MAX_SCAN_IPS})
    scope_error = _scope_error(ip_addresses)
    if scope_error:
        errors.insert(0, scope_error)
    return jsonify({
        "valid": bool(ip_addresses) and not errors,
        "count": len(ip_addresses),
        "sample": ip_addresses[:10],
        "errors": errors[:50],
        "limit": MAX_SCAN_IPS,
    })

@app.route('/parse_csv', methods=['POST'])
@login_required
def parse_csv():
    from subnet_utils import parse_csv_file

    data = request.get_json(silent=True) or {}
    csv_content = data.get('csv_content')
    if not csv_content or not isinstance(csv_content, str):
        return _json_error("No CSV content provided")
    if len(csv_content) > 5 * 1024 * 1024:
        return _json_error("CSV file is too large (max 5 MB)")
    errors = []
    try:
        ip_addresses = parse_csv_file(csv_content, errors=errors)
    except ValueError as e:
        return _json_error(str(e))
    if not ip_addresses:
        return _json_error("No valid IP addresses found in the CSV file")
    return jsonify({
        "success": True,
        "count": len(ip_addresses),
        "subnets": "\n".join(ip_addresses),
        "errors": errors[:50],
    })

@app.route('/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    from models import ScanResult

    scan_session = _get_visible_scan_or_404(scan_id)
    total_ips = scan_session.total_ips or 0
    completed_ips = ScanResult.query.filter(
        ScanResult.scan_session_id == scan_id,
        ScanResult.status_code.in_(['success', 'failed'])
    ).count()

    return jsonify({
        "scan_id": scan_id,
        "status": scan_session.status,
        "total": total_ips,
        "completed": completed_ips,
        "percent_complete": min(completed_ips / total_ips * 100, 100) if total_ips > 0 else 0
    })

@app.route('/results')
@login_required
def results():
    from models import ScanSession, result_counts

    visible = _visible_scans()
    scan_sessions = visible.order_by(ScanSession.created_at.desc()).all()
    counts = result_counts(visible.with_entities(ScanSession.id).scalar_subquery()) if scan_sessions else {}
    current_scan_id = session.get('current_scan_id')

    return render_template('results.html', scan_sessions=scan_sessions, counts=counts,
                           current_scan_id=current_scan_id)

@app.route('/scan_results/<int:scan_id>')
@login_required
def scan_results(scan_id):
    """Result list for one scan, without the large output columns.

    Command output and server info for one host come from scan_result_detail.
    """
    from sqlalchemy.orm import load_only
    from models import ScanResult, result_counts

    scan_session = _get_visible_scan_or_404(scan_id)
    # Load only the light columns; command_output/server_info can be megabytes per host
    results = (ScanResult.query.filter_by(scan_session_id=scan_id)
               .options(load_only(ScanResult.id, ScanResult.scan_session_id, ScanResult.ip_address,
                                  ScanResult.status_code, ScanResult.ssh_status, ScanResult.sudo_status,
                                  ScanResult.command_status, ScanResult.error_message,
                                  ScanResult.execution_time, ScanResult.created_at))
               .all())
    counts = result_counts([scan_id]).get(scan_id, {'success': 0, 'failed': 0, 'total': 0})
    total = counts['total']

    return jsonify({
        "scan_id": scan_id,
        "session": scan_session.to_dict(counts=counts),
        "results": [r.to_dict(include_output=False) for r in results],
        "summary": {
            "total": total,
            "success": counts['success'],
            "failed": counts['failed'],
            "success_rate": (counts['success'] / total * 100) if total > 0 else 0
        }
    })


@app.route('/scan_results/<int:scan_id>/result/<int:result_id>')
@login_required
def scan_result_detail(scan_id, result_id):
    """Full result for one host, including command output and server info."""
    from models import ScanResult

    _get_visible_scan_or_404(scan_id)
    result = db.session.get(ScanResult, result_id)
    if result is None or result.scan_session_id != scan_id:
        return _json_error("Result not found", 404)
    return jsonify(result.to_dict())

@app.route('/api/delete_scan/<int:scan_id>', methods=['DELETE'])
@admin_required
def delete_scan(scan_id):
    from models import ScanSession, scheduled_scan_sessions, scan_session_credentials

    scan_session = db.session.get(ScanSession, scan_id)
    if scan_session is None:
        return _json_error("Scan not found", 404)
    if scan_session.status == 'running':
        return _json_error("Cannot delete a scan that is still running", 409)
    db.session.execute(scheduled_scan_sessions.delete().where(
        scheduled_scan_sessions.c.scan_session_id == scan_id))
    db.session.execute(scan_session_credentials.delete().where(
        scan_session_credentials.c.scan_session_id == scan_id))
    db.session.delete(scan_session)
    db.session.commit()
    audit('scan.delete', f"scan:{scan_id}")
    if session.get('current_scan_id') == scan_id:
        session.pop('current_scan_id', None)
    return jsonify({"success": True})


_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def _csv_safe(value):
    """Neutralize spreadsheet formulas in exported cells (CSV injection)."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _fmt_dt(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC') if dt else None


def _build_pdf_report(scan_id, scan_session, results, success_count, failed_count):
    """Render a one-page PDF summary using matplotlib's object API (thread-safe, no pyplot)."""
    from io import BytesIO
    from matplotlib.figure import Figure
    from models import utcnow

    fig = Figure(figsize=(11, 8))
    fig.suptitle(f'Subnet Whisperer Scan Results (ID: {scan_id})', fontsize=16)
    fig.text(0.1, 0.92, f'Generated: {_fmt_dt(utcnow())}')
    # parse_math=False: a '$' in a username must not be parsed as mathtext
    fig.text(0.1, 0.90, f'Username: {scan_session.username}', parse_math=False)
    fig.text(0.1, 0.88, f'Authentication: {scan_session.auth_type}')
    fig.text(0.1, 0.86, f'Started: {_fmt_dt(scan_session.started_at) or "N/A"}')
    fig.text(0.1, 0.84, f'Completed: {_fmt_dt(scan_session.completed_at) or "N/A"}')

    ax_pie = fig.add_subplot(2, 2, 1)
    if success_count + failed_count > 0:
        ax_pie.pie([success_count, failed_count], labels=['Success', 'Failed'],
                   autopct='%1.1f%%', colors=['#28a745', '#dc3545'])
    else:
        ax_pie.text(0.5, 0.5, 'No results', ha='center', va='center')
        ax_pie.axis('off')
    ax_pie.set_title('Scan Results')

    status_categories = {}
    for r in results:
        status_categories[r.status_code] = status_categories.get(r.status_code, 0) + 1
    ax_bar = fig.add_subplot(2, 2, 2)
    if status_categories:
        ax_bar.bar(list(status_categories.keys()), list(status_categories.values()))
        ax_bar.set_title('Status Breakdown')
        ax_bar.tick_params(axis='x', labelrotation=45)
    else:
        ax_bar.axis('off')

    ax_table = fig.add_subplot(2, 1, 2)
    ax_table.axis('off')
    if results:
        rows = [[r.ip_address, r.status_code, 'Yes' if r.ssh_status else 'No',
                 'Yes' if r.command_status else 'No',
                 f"{r.execution_time:.2f}" if r.execution_time is not None else '']
                for r in results[:20]]
        table = ax_table.table(
            cellText=rows,
            colLabels=['IP Address', 'Status', 'SSH Status', 'Command Status', 'Execution Time (s)'],
            loc='center', cellLoc='center')
        table.auto_set_font_size(False)
        table.set_fontsize(8)
        table.scale(1, 1.5)
        ax_table.set_title('Scan Results (First 20 rows)')
        if len(results) > 20:
            fig.text(0.5, 0.05, f'... and {len(results) - 20} more results',
                     ha='center', fontsize=8, style='italic')

    fig.tight_layout(rect=[0, 0, 1, 0.8])
    buffer = BytesIO()
    fig.savefig(buffer, format='pdf')
    return buffer.getvalue()


@app.route('/scan_results/<int:scan_id>/export/<format>')
@login_required
def export_results(scan_id, format):
    """Export scan results in various formats (CSV, JSON, PDF)"""
    import csv
    import json
    from io import StringIO
    from models import ScanResult, utcnow

    format = format.lower()
    if format not in ('csv', 'json', 'pdf'):
        return _json_error('Unsupported export format')

    scan_session = _get_visible_scan_or_404(scan_id)
    results = ScanResult.query.filter_by(scan_session_id=scan_id).all()
    audit('scan.export', f"scan:{scan_id}", details=f"format={format}")

    try:
        # Generate timestamp for filename
        timestamp = utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"subnet_whisperer_results_{scan_id}_{timestamp}"

        # Calculate summary statistics
        total = len(results)
        success_count = sum(1 for r in results if r.status_code == 'success')
        failed_count = total - success_count
        success_rate = (success_count / total * 100) if total > 0 else 0

        if format == 'csv':
            output = StringIO()
            csv_writer = csv.writer(output)
            csv_writer.writerow(['IP Address', 'Status', 'SSH Status', 'Sudo Status', 'Command Status',
                                 'Execution Time (s)', 'Error Message', 'Created At (UTC)'])
            for result in results:
                csv_writer.writerow([_csv_safe(v) for v in [
                    result.ip_address,
                    result.status_code,
                    'Yes' if result.ssh_status else 'No',
                    'Yes' if result.sudo_status else 'No',
                    'Yes' if result.command_status else 'No',
                    result.execution_time,
                    result.error_message,
                    result.created_at.strftime('%Y-%m-%d %H:%M:%S') if result.created_at else ''
                ]])
            response = make_response(output.getvalue())
            response.headers["Content-Disposition"] = f"attachment; filename={filename}.csv"
            response.headers["Content-Type"] = "text/csv; charset=utf-8"
            return response

        if format == 'json':
            export_data = {
                'scan_id': scan_id,
                'username': scan_session.username,
                'auth_type': scan_session.auth_type,
                'status': scan_session.status,
                'started_at': _fmt_dt(scan_session.started_at),
                'completed_at': _fmt_dt(scan_session.completed_at),
                'summary': {
                    'total': total,
                    'success': success_count,
                    'failed': failed_count,
                    'success_rate': success_rate
                },
                'results': [r.to_dict() for r in results]
            }
            response = make_response(json.dumps(export_data, indent=2))
            response.headers["Content-Disposition"] = f"attachment; filename={filename}.json"
            response.headers["Content-Type"] = "application/json"
            return response

        pdf_bytes = _build_pdf_report(scan_id, scan_session, results, success_count, failed_count)
        response = make_response(pdf_bytes)
        response.headers["Content-Disposition"] = f"attachment; filename={filename}.pdf"
        response.headers["Content-Type"] = "application/pdf"
        return response

    except Exception:
        logger.exception("Export of scan %s as %s failed", scan_id, format)
        return _json_error('Export failed; see server logs for details', 500)

@app.route('/templates', methods=['GET', 'POST'])
@login_required
def templates():
    from forms import CommandTemplateForm
    from models import CommandTemplate

    form = CommandTemplateForm()

    if request.method == 'POST':
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('templates'))
        if form.validate_on_submit():
            name = form.name.data.strip()
            if CommandTemplate.query.filter_by(name=name).first():
                flash(f'A template named "{name}" already exists.', 'danger')
            else:
                template = CommandTemplate(
                    name=name,
                    description=form.description.data,
                    commands=form.commands.data
                )
                db.session.add(template)
                db.session.commit()
                audit('template.create', f"template:{template.id}", details=f"name={name}")
                flash('Template created successfully!', 'success')
                return redirect(url_for('templates'))

    templates = CommandTemplate.query.order_by(CommandTemplate.name).all()
    return render_template('templates.html', form=form, templates=templates)

@app.route('/template/<int:template_id>', methods=['GET'])
@login_required
def get_template(template_id):
    from models import CommandTemplate

    template = db.get_or_404(CommandTemplate, template_id)
    return jsonify(template.to_dict())

@app.route('/template/<int:template_id>', methods=['PUT'])
@admin_required
def update_template(template_id):
    from models import CommandTemplate

    template = db.session.get(CommandTemplate, template_id)
    if template is None:
        return _json_error("Template not found", 404)
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    commands = data.get('commands') or ''
    if not name or not isinstance(commands, str) or not commands.strip():
        return _json_error("Name and commands are required")
    if len(name) > 100:
        return _json_error("Name must be at most 100 characters")
    duplicate = CommandTemplate.query.filter(CommandTemplate.name == name,
                                             CommandTemplate.id != template_id).first()
    if duplicate:
        return _json_error(f'A template named "{name}" already exists', 409)
    template.name = name
    template.description = data.get('description') or ''
    template.commands = commands
    db.session.commit()
    audit('template.update', f"template:{template_id}", details=f"name={name}")
    return jsonify({"success": True, "template": template.to_dict()})

@app.route('/template/<int:template_id>', methods=['DELETE'])
@admin_required
def delete_template(template_id):
    from models import CommandTemplate, ScheduledScan

    template = db.session.get(CommandTemplate, template_id)
    if template is None:
        return _json_error("Template not found", 404)
    # Detach schedules that referenced this template
    ScheduledScan.query.filter_by(command_template_id=template_id).update(
        {ScheduledScan.command_template_id: None})
    name = template.name
    db.session.delete(template)
    db.session.commit()
    audit('template.delete', f"template:{template_id}", details=f"name={name}")
    return jsonify({"success": True})

@app.route('/schedules')
@admin_required
def schedules():
    from models import ScheduledScan, ScanSession, scheduled_scan_sessions, _iso

    scheduled_scans = ScheduledScan.query.order_by(ScheduledScan.created_at.desc()).all()

    # Recent scan sessions, labelled with their schedule name when they came from one
    recent_sessions = []
    try:
        rows = (db.session.query(ScanSession, ScheduledScan.name)
                .outerjoin(scheduled_scan_sessions,
                           scheduled_scan_sessions.c.scan_session_id == ScanSession.id)
                .outerjoin(ScheduledScan,
                           ScheduledScan.id == scheduled_scan_sessions.c.scheduled_scan_id)
                .order_by(ScanSession.started_at.desc())
                .limit(10).all())
        recent_sessions = [{
            'id': s.id,
            'username': s.username,
            'started_at': _iso(s.started_at),
            'status': s.status,
            'schedule_name': name or 'Manual Scan',
        } for s, name in rows]
    except Exception as e:
        logger.error(f"Error fetching recent scan sessions: {str(e)}")

    return render_template('schedules.html', scheduled_scans=scheduled_scans, recent_sessions=recent_sessions)


def _populate_schedule_choices(form):
    from models import CommandTemplate, CredentialSet
    templates = CommandTemplate.query.order_by(CommandTemplate.name).all()
    form.command_template.choices = [(0, 'None')] + [(t.id, t.name) for t in templates]
    credential_sets = CredentialSet.query.order_by(CredentialSet.priority.desc()).all()
    form.credential_set_id.choices = [(0, 'None (use the credentials above)')] + [
        (c.id, f"{c.username} ({c.auth_type})" + (f" - {c.description}" if c.description else ''))
        for c in credential_sets]


def _apply_schedule_form(scheduled_scan, form, is_new):
    """Copy form data onto a ScheduledScan, encrypting secrets. Returns an error message or None."""
    from encryption_utils import encrypt_data
    from models import CredentialSet, utcnow

    credential_set = None
    if form.credential_set_id.data:
        credential_set = db.session.get(CredentialSet, form.credential_set_id.data)
        if credential_set is None:
            return 'Selected credential set does not exist.'

    scheduled_scan.name = form.name.data
    scheduled_scan.description = form.description.data
    scheduled_scan.subnets = form.subnets.data
    scheduled_scan.credential_set_id = credential_set.id if credential_set else None
    scheduled_scan.username = credential_set.username if credential_set else form.username.data
    scheduled_scan.auth_type = credential_set.auth_type if credential_set else form.auth_type.data
    scheduled_scan.port = form.port.data or 22
    scheduled_scan.command_template_id = form.command_template.data or None
    scheduled_scan.custom_commands = form.custom_commands.data
    scheduled_scan.collect_server_info = form.collect_server_info.data
    scheduled_scan.collect_detailed_info = form.collect_detailed_info.data
    scheduled_scan.concurrency = form.concurrency.data
    scheduled_scan.schedule_frequency = form.schedule_frequency.data
    scheduled_scan.custom_interval_minutes = form.custom_interval_minutes.data
    scheduled_scan.start_date = form.start_date.data
    scheduled_scan.end_date = form.end_date.data
    scheduled_scan.is_active = form.is_active.data

    keep_password = not is_new and request.form.get('keep_existing_password') == 'on'
    keep_key = not is_new and request.form.get('keep_existing_key') == 'on'
    keep_sudo = not is_new and request.form.get('keep_existing_sudo_password') == 'on'

    if not credential_set:
        if form.auth_type.data == 'password':
            if form.password.data and not keep_password:
                scheduled_scan.password_encrypted = encrypt_data(form.password.data)
            if not scheduled_scan.password_encrypted:
                return 'Password is required when using password authentication.'
            scheduled_scan.private_key_encrypted = None
            scheduled_scan.private_key_passphrase_encrypted = None
        else:
            if form.private_key.data and not keep_key:
                scheduled_scan.private_key_encrypted = encrypt_data(form.private_key.data)
                # A new key replaces the old passphrase (blank = key has no passphrase)
                scheduled_scan.private_key_passphrase_encrypted = (
                    encrypt_data(form.private_key_passphrase.data) if form.private_key_passphrase.data else None)
            elif form.private_key_passphrase.data:
                scheduled_scan.private_key_passphrase_encrypted = encrypt_data(form.private_key_passphrase.data)
            if not scheduled_scan.private_key_encrypted:
                return 'Private key is required when using key authentication.'
            scheduled_scan.password_encrypted = None
    else:
        # The credential set supplies the secrets
        scheduled_scan.password_encrypted = None
        scheduled_scan.private_key_encrypted = None
        scheduled_scan.private_key_passphrase_encrypted = None

    if not keep_sudo:
        # Unchecking "keep" with a blank field clears the stored sudo password
        scheduled_scan.sudo_password_encrypted = (
            encrypt_data(form.sudo_password.data) if form.sudo_password.data else None)

    # Validate the subnet list now rather than failing at run time
    from subnet_utils import parse_subnet_input
    try:
        ip_addresses = parse_subnet_input(form.subnets.data or '')
        if not ip_addresses:
            return 'No valid IP addresses found in the subnets field.'
    except ValueError as e:
        return str(e)
    scope_error = _scope_error(ip_addresses)
    if scope_error:
        return scope_error

    commands = []
    if scheduled_scan.command_template_id:
        from models import CommandTemplate
        template = db.session.get(CommandTemplate, scheduled_scan.command_template_id)
        commands = _split_commands(template.commands if template else '')
    commands.extend(_split_commands(form.custom_commands.data))
    policy_error = _command_policy_error(commands)
    if policy_error:
        return policy_error

    if form.end_date.data and form.end_date.data <= utcnow() and form.is_active.data:
        return 'End date is in the past; the schedule would never run.'

    scheduled_scan.last_run = None if is_new else scheduled_scan.last_run
    scheduled_scan.calculate_next_run()
    return None


@app.route('/schedules/create', methods=['GET', 'POST'])
@admin_required
def create_schedule():
    from forms import ScheduledScanForm
    from models import ScheduledScan, utcnow

    form = ScheduledScanForm()
    _populate_schedule_choices(form)

    if form.validate_on_submit():
        scheduled_scan = ScheduledScan(owner_id=current_user.id)
        error = _apply_schedule_form(scheduled_scan, form, is_new=True)
        if error:
            flash(error, 'danger')
        else:
            db.session.add(scheduled_scan)
            db.session.commit()
            audit('schedule.create', f"schedule:{scheduled_scan.id}",
                  details=f"name={scheduled_scan.name} frequency={scheduled_scan.schedule_frequency} "
                          f"credential_set={scheduled_scan.credential_set_id}")
            flash('Scheduled scan created successfully!', 'success')
            return redirect(url_for('schedules'))

    # Set default values
    if not form.start_date.data:
        form.start_date.data = utcnow()

    return render_template('schedule_form.html', form=form, schedule=None)

@app.route('/schedules/<int:schedule_id>', methods=['GET'])
@admin_required
def view_schedule(schedule_id):
    from models import ScheduledScan

    scheduled_scan = db.get_or_404(ScheduledScan, schedule_id)
    return render_template('schedule_detail.html', schedule=scheduled_scan)

@app.route('/schedules/<int:schedule_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_schedule(schedule_id):
    from forms import ScheduledScanForm
    from models import ScheduledScan

    scheduled_scan = db.get_or_404(ScheduledScan, schedule_id)
    if request.method == 'GET':
        form = ScheduledScanForm(obj=scheduled_scan)
        # obj= maps the relationship object, not the id; set the select values explicitly
        form.command_template.data = scheduled_scan.command_template_id or 0
        form.credential_set_id.data = scheduled_scan.credential_set_id or 0
        form.port.data = scheduled_scan.port or 22
    else:
        form = ScheduledScanForm()
    form.is_edit = True
    _populate_schedule_choices(form)

    if form.validate_on_submit():
        error = _apply_schedule_form(scheduled_scan, form, is_new=False)
        if error:
            db.session.rollback()
            flash(error, 'danger')
        else:
            db.session.commit()
            audit('schedule.update', f"schedule:{schedule_id}",
                  details=f"name={scheduled_scan.name} active={scheduled_scan.is_active} "
                          f"credential_set={scheduled_scan.credential_set_id}")
            flash('Scheduled scan updated successfully!', 'success')
            return redirect(url_for('schedules'))

    # Add property to check if private key exists
    scheduled_scan.has_private_key = bool(scheduled_scan.private_key_encrypted)

    return render_template('schedule_form.html', form=form, schedule=scheduled_scan)

@app.route('/schedules/<int:schedule_id>/activate', methods=['POST'])
@admin_required
def activate_schedule(schedule_id):
    from models import ScheduledScan

    scheduled_scan = db.get_or_404(ScheduledScan, schedule_id)
    scheduled_scan.is_active = True
    scheduled_scan.calculate_next_run()
    if not scheduled_scan.is_active:
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": f"Schedule '{scheduled_scan.name}' has passed its end date; edit the end date to reactivate it"
        }), 400
    db.session.commit()
    audit('schedule.activate', f"schedule:{schedule_id}")

    return jsonify({
        "success": True,
        "message": f"Schedule '{scheduled_scan.name}' activated successfully"
    })

@app.route('/schedules/<int:schedule_id>/deactivate', methods=['POST'])
@admin_required
def deactivate_schedule(schedule_id):
    from models import ScheduledScan

    scheduled_scan = db.get_or_404(ScheduledScan, schedule_id)
    scheduled_scan.is_active = False
    scheduled_scan.next_run = None
    db.session.commit()
    audit('schedule.deactivate', f"schedule:{schedule_id}")

    return jsonify({
        "success": True,
        "message": f"Schedule '{scheduled_scan.name}' deactivated successfully"
    })

@app.route('/schedules/<int:schedule_id>/delete', methods=['POST'])
@admin_required
def delete_schedule(schedule_id):
    from models import ScheduledScan, scheduled_scan_sessions

    scheduled_scan = db.get_or_404(ScheduledScan, schedule_id)
    schedule_name = scheduled_scan.name
    db.session.execute(scheduled_scan_sessions.delete().where(
        scheduled_scan_sessions.c.scheduled_scan_id == schedule_id))
    db.session.delete(scheduled_scan)
    db.session.commit()
    audit('schedule.delete', f"schedule:{schedule_id}", details=f"name={schedule_name}")

    return jsonify({
        "success": True,
        "message": f"Schedule '{schedule_name}' deleted successfully"
    })


def _save_credential_set(credential_set, form, is_new):
    """Apply CredentialSetForm data to a credential set. Returns an error message or None."""
    from encryption_utils import encrypt_data

    auth_type = form.auth_type.data
    if auth_type not in ('password', 'key'):
        return 'Invalid authentication type.'
    auth_changed = not is_new and credential_set.auth_type != auth_type

    credential_set.username = form.username.data
    credential_set.auth_type = auth_type
    credential_set.description = form.description.data
    credential_set.priority = form.priority.data

    from subnet_utils import parse_network_list
    subnet_errors = []
    networks = parse_network_list(form.allowed_subnets.data, subnet_errors)
    if subnet_errors:
        return 'Allowed subnets: ' + '; '.join(subnet_errors[:5])
    credential_set.allowed_subnets = ', '.join(str(n) for n in networks) or None

    if auth_type == 'password':
        if form.password.data:
            credential_set.password_encrypted = encrypt_data(form.password.data)
        elif is_new or auth_changed or not credential_set.password_encrypted:
            return 'A password is required for password authentication.'
        credential_set.private_key_encrypted = None
        credential_set.private_key_passphrase_encrypted = None
    else:
        if form.private_key.data:
            credential_set.private_key_encrypted = encrypt_data(form.private_key.data)
            # A new key replaces the old passphrase (blank = key has no passphrase)
            credential_set.private_key_passphrase_encrypted = (
                encrypt_data(form.private_key_passphrase.data) if form.private_key_passphrase.data else None)
        elif is_new or auth_changed or not credential_set.private_key_encrypted:
            return 'A private key is required for key authentication.'
        elif form.private_key_passphrase.data:
            credential_set.private_key_passphrase_encrypted = encrypt_data(form.private_key_passphrase.data)
        credential_set.password_encrypted = None

    if form.sudo_password.data:
        credential_set.sudo_password_encrypted = encrypt_data(form.sudo_password.data)
    elif not is_new and request.form.get('clear_sudo_password') == 'on':
        credential_set.sudo_password_encrypted = None
    return None


@app.route('/credentials', methods=['GET', 'POST'])
@admin_required
def credentials():
    from forms import CredentialSetForm
    from models import CredentialSet

    form = CredentialSetForm()

    if form.validate_on_submit():
        credential_set = CredentialSet()
        error = _save_credential_set(credential_set, form, is_new=True)
        if error:
            flash(error, 'danger')
        else:
            db.session.add(credential_set)
            db.session.commit()
            _audit_credential('credential.create', credential_set)
            flash('Credential set created successfully!', 'success')
            return redirect(url_for('credentials'))

    credential_sets = CredentialSet.query.order_by(CredentialSet.priority.desc()).all()
    return render_template('credentials.html', form=form, credential_sets=credential_sets)


def _audit_credential(action, credential_set):
    audit(action, f"credential_set:{credential_set.id}",
          details=f"ssh_user={credential_set.username} auth={credential_set.auth_type} "
                  f"allowed_subnets={credential_set.allowed_subnets or 'any'}")


def _form_error_text(form):
    return '; '.join(f"{getattr(form, name).label.text}: {', '.join(errs)}"
                     for name, errs in form.errors.items() if hasattr(form, name))


@app.route('/add_credential', methods=['POST'])
@admin_required
def add_credential():
    from forms import CredentialSetForm
    from models import CredentialSet

    form = CredentialSetForm()

    if form.validate_on_submit():
        credential_set = CredentialSet()
        error = _save_credential_set(credential_set, form, is_new=True)
        if error:
            flash(error, 'danger')
        else:
            db.session.add(credential_set)
            db.session.commit()
            _audit_credential('credential.create', credential_set)
            flash('Credential set created successfully!', 'success')
    else:
        flash('Error creating credential set: ' + _form_error_text(form), 'danger')

    return redirect(url_for('credentials'))

@app.route('/edit_credential', methods=['POST'])
@admin_required
def edit_credential():
    from forms import CredentialSetForm
    from models import CredentialSet

    form = CredentialSetForm()

    if form.validate_on_submit():
        try:
            credential_set = db.session.get(CredentialSet, int(form.id.data))
        except (TypeError, ValueError):
            credential_set = None
        if credential_set is None:
            abort(404)
        error = _save_credential_set(credential_set, form, is_new=False)
        if error:
            db.session.rollback()
            flash(error, 'danger')
        else:
            db.session.commit()
            _audit_credential('credential.update', credential_set)
            flash('Credential set updated successfully!', 'success')
    else:
        flash('Error updating credential set: ' + _form_error_text(form), 'danger')

    return redirect(url_for('credentials'))

@app.route('/delete_credential', methods=['POST'])
@admin_required
def delete_credential():
    from models import CredentialSet, ScheduledScan, scan_session_credentials

    try:
        credential_id = int(request.form.get('credential_id', ''))
    except ValueError:
        abort(400)
    credential_set = db.session.get(CredentialSet, credential_id)
    if credential_set is None:
        abort(404)

    in_use = ScheduledScan.query.filter_by(credential_set_id=credential_id).count()
    if in_use:
        flash(f'Credential set is used by {in_use} scheduled scan(s); change those schedules first.', 'danger')
        return redirect(url_for('credentials'))

    db.session.execute(scan_session_credentials.delete().where(
        scan_session_credentials.c.credential_set_id == credential_id))
    db.session.delete(credential_set)
    db.session.commit()
    audit('credential.delete', f"credential_set:{credential_id}")

    flash('Credential set deleted successfully!', 'success')
    return redirect(url_for('credentials'))

@app.route('/credential/<int:credential_id>')
@admin_required
def get_credential(credential_id):
    from models import CredentialSet

    credential_set = db.get_or_404(CredentialSet, credential_id)
    return jsonify(credential_set.to_dict())

@app.route('/settings')
@admin_required
def settings():
    """Read-only view of the effective configuration (set through environment variables)."""
    import ssh_utils
    import subnet_utils
    import encryption_utils
    from security_utils import sanitization_mode
    from scheduler import scheduler_service

    if os.environ.get('ENCRYPTION_KEY'):
        key_source = 'ENCRYPTION_KEY environment variable'
    elif os.path.exists(encryption_utils.KEY_FILE_PATH):
        key_source = 'instance/.encryption_key file'
    else:
        key_source = 'Derived from FLASK_SECRET_KEY / SECRET_KEY (legacy)'

    policy = ssh_utils._host_key_policy_name()
    policy_labels = {
        'tofu': 'Trust on first use (unknown keys are recorded; changed keys are rejected)',
        'reject': 'Reject hosts that are not already in known_hosts',
        'warn': 'Accept any host key (no verification)',
    }
    mode_labels = {
        'allowlist': 'Allowlist: only command lines from approved templates may run',
        'enabled': 'Enabled (denylist): shell operators and restricted commands are blocked',
        'disabled': 'Disabled: only obviously destructive commands are blocked',
    }
    scope = ', '.join(str(n) for n in subnet_utils.SCAN_ALLOWED_NETWORKS) or 'Unrestricted'
    config = [
        ('Command policy (COMMAND_SANITIZATION)', mode_labels[sanitization_mode()]),
        ('Authorised scan scope (SCAN_ALLOWED_SUBNETS)', scope),
        ('Login lockout (LOGIN_MAX_FAILURES / LOGIN_LOCKOUT_MINUTES)',
         f'{login_throttle.max_failures} failures per user and address, '
         f'{login_throttle.ip_max_failures} per address, within {login_throttle.window // 60} minutes'),
        ('SSH host keys (SSH_HOST_KEY_POLICY)', policy_labels[policy]),
        ('Command timeout (SSH_COMMAND_TIMEOUT)', f'{ssh_utils.SSH_COMMAND_TIMEOUT} seconds'),
        ('Connection timeout (SSH_CONNECT_TIMEOUT)', f'{ssh_utils.SSH_CONNECT_TIMEOUT} seconds'),
        ('Output kept per command stream (SSH_MAX_OUTPUT_BYTES)', f'{ssh_utils.MAX_OUTPUT_BYTES:,} bytes'),
        ('Maximum IPs per scan (MAX_SCAN_IPS)', f'{subnet_utils.MAX_SCAN_IPS:,}'),
        ('Maximum concurrency (MAX_CONCURRENCY)', str(ssh_utils.MAX_CONCURRENCY)),
        ('Scheduler (START_SCHEDULER)', 'Running' if scheduler_service.running else 'Stopped'),
        ('Database', db.engine.dialect.name),
        ('Encryption key source', key_source),
        ('Secure session cookie (SESSION_COOKIE_SECURE)', 'On' if app.config['SESSION_COOKIE_SECURE'] else 'Off'),
    ]
    return render_template('settings.html', config=config)

AUDIT_PAGE_SIZE = 100


@app.route('/audit')
@admin_required
def audit_log():
    """Read-only view of the security audit trail."""
    from models import AuditLog
    page = request.args.get('page', 1, type=int) or 1
    action = (request.args.get('action') or '').strip()
    query = AuditLog.query
    if action:
        query = query.filter(AuditLog.action.startswith(action, autoescape=True))
    pagination = db.paginate(query.order_by(AuditLog.id.desc()), page=max(page, 1),
                             per_page=AUDIT_PAGE_SIZE, error_out=False)
    return render_template('audit.html', entries=pagination.items, pagination=pagination, action=action)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


# Start the background scheduler for recurring scans (disable with START_SCHEDULER=false)
if _env_flag('START_SCHEDULER', default=True):
    from scheduler import start_scheduler
    start_scheduler()
