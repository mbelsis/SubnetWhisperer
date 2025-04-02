import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
import uuid

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Setup base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", str(uuid.uuid4()))

# Configure SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///subnet_whisperer.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database with the app
db.init_app(app)

# Import routes and models after initializing app and db
with app.app_context():
    from models import ScanResult, CommandTemplate, ScanSession
    import ssh_utils
    import subnet_utils
    from forms import ScanForm, CommandTemplateForm
    
    # Create database tables
    db.create_all()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    from forms import ScanForm
    from models import CommandTemplate
    
    form = ScanForm()
    templates = CommandTemplate.query.all()
    
    # Populate form choices
    form.command_template.choices = [(t.id, t.name) for t in templates]
    
    if form.validate_on_submit():
        # Process the form data and start scan
        flash('Scan initiated successfully!', 'success')
        return redirect(url_for('results'))
    
    return render_template('scan.html', form=form, templates=templates)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    from subnet_utils import parse_subnet_input
    from ssh_utils import start_scan_session
    from models import ScanSession, CommandTemplate
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    subnets = data.get('subnets', '')
    username = data.get('username', '')
    auth_type = data.get('auth_type', 'password')
    password = data.get('password', '') if auth_type == 'password' else None
    private_key = data.get('private_key', '') if auth_type == 'key' else None
    template_id = data.get('template_id')
    collect_server_info = data.get('collect_server_info', False)
    concurrency = int(data.get('concurrency', 10))
    
    # Validate input
    if not subnets or not username or (auth_type == 'password' and not password) or (auth_type == 'key' and not private_key):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Parse subnets
    try:
        ip_addresses = parse_subnet_input(subnets)
        if not ip_addresses:
            return jsonify({"error": "No valid IP addresses found"}), 400
    except Exception as e:
        return jsonify({"error": f"Error parsing subnets: {str(e)}"}), 400
    
    # Get command template
    commands = []
    if template_id:
        template = CommandTemplate.query.get(template_id)
        if template:
            commands = template.commands.splitlines()
    
    # Create a new scan session
    scan_session = ScanSession(
        username=username,
        auth_type=auth_type,
        collect_server_info=collect_server_info
    )
    db.session.add(scan_session)
    db.session.commit()
    
    # Store session ID in session
    session['current_scan_id'] = scan_session.id
    
    # Start scan in background
    start_scan_session(
        scan_session.id,
        ip_addresses,
        username,
        password,
        private_key,
        commands,
        collect_server_info,
        concurrency
    )
    
    return jsonify({
        "success": True,
        "scan_id": scan_session.id,
        "message": f"Scan started with {len(ip_addresses)} IP addresses"
    })

@app.route('/scan_status/<int:scan_id>')
def scan_status(scan_id):
    from models import ScanSession, ScanResult
    
    scan_session = ScanSession.query.get_or_404(scan_id)
    total_ips = ScanResult.query.filter_by(scan_session_id=scan_id).count()
    completed_ips = ScanResult.query.filter(
        ScanResult.scan_session_id == scan_id,
        ScanResult.status_code.in_(['success', 'failed'])
    ).count()
    
    return jsonify({
        "scan_id": scan_id,
        "status": scan_session.status,
        "total": total_ips,
        "completed": completed_ips,
        "percent_complete": (completed_ips / total_ips * 100) if total_ips > 0 else 0
    })

@app.route('/results')
def results():
    from models import ScanSession
    
    scan_sessions = ScanSession.query.order_by(ScanSession.created_at.desc()).all()
    current_scan_id = session.get('current_scan_id')
    
    return render_template('results.html', scan_sessions=scan_sessions, current_scan_id=current_scan_id)

@app.route('/scan_results/<int:scan_id>')
def scan_results(scan_id):
    from models import ScanResult
    
    results = ScanResult.query.filter_by(scan_session_id=scan_id).all()
    return jsonify({
        "scan_id": scan_id,
        "results": [r.to_dict() for r in results]
    })

@app.route('/templates', methods=['GET', 'POST'])
def templates():
    from forms import CommandTemplateForm
    from models import CommandTemplate
    
    form = CommandTemplateForm()
    templates = CommandTemplate.query.all()
    
    if form.validate_on_submit():
        template = CommandTemplate(
            name=form.name.data,
            description=form.description.data,
            commands=form.commands.data
        )
        db.session.add(template)
        db.session.commit()
        flash('Template created successfully!', 'success')
        return redirect(url_for('templates'))
    
    return render_template('templates.html', form=form, templates=templates)

@app.route('/template/<int:template_id>', methods=['GET'])
def get_template(template_id):
    from models import CommandTemplate
    
    template = CommandTemplate.query.get_or_404(template_id)
    return jsonify(template.to_dict())

@app.route('/template/<int:template_id>', methods=['DELETE'])
def delete_template(template_id):
    from models import CommandTemplate
    
    template = CommandTemplate.query.get_or_404(template_id)
    db.session.delete(template)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500
