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
    from models import ScanResult, CommandTemplate, ScanSession, ScheduledScan, CredentialSet
    import ssh_utils
    import subnet_utils
    from forms import ScanForm, CommandTemplateForm, ScheduledScanForm
    
    # Create database tables
    db.create_all()
    
    # Run migrations if needed
    try:
        from migrations.scheduled_scans import migrate_database
        migrate_database()
    except Exception as e:
        logger.error(f"Error running migration: {str(e)}")

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    from forms import ScanForm
    from models import CommandTemplate, CredentialSet
    
    form = ScanForm()
    templates = CommandTemplate.query.all()
    credential_sets = CredentialSet.query.order_by(CredentialSet.priority.desc()).all()
    
    # Populate form choices
    form.command_template.choices = [(t.id, t.name) for t in templates]
    
    if form.validate_on_submit():
        # Process the form data and start scan
        flash('Scan initiated successfully!', 'success')
        return redirect(url_for('results'))
    
    return render_template('scan.html', form=form, templates=templates, credential_sets=credential_sets)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    from subnet_utils import parse_subnet_input
    from ssh_utils import start_scan_session
    from models import ScanSession, CommandTemplate, CredentialSet
    
    # Check if data is JSON or form data
    if request.is_json:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Get JSON data fields
        subnets = data.get('subnets', '')
        username = data.get('username', '')
        auth_type = data.get('auth_type', 'password')
        password = data.get('password', '') if auth_type == 'password' else None
        private_key = data.get('private_key', '') if auth_type == 'key' else None
        template_id = data.get('template_id')
        custom_commands = data.get('custom_commands', '')
        collect_server_info = bool(data.get('collect_server_info', False))
        collect_detailed_info = bool(data.get('collect_detailed_info', False))
        concurrency = int(data.get('concurrency', 10))
        sudo_password = data.get('sudo_password')
        use_credential_sets = bool(data.get('use_credential_sets', False))
        multiple_credentials = bool(data.get('multiple_credentials', False))
        credential_set_id = data.get('credential_set_id')
    else:
        # Get form data
        subnets = request.form.get('subnets', '')
        collect_server_info = request.form.get('collectServerInfo') == 'on'
        collect_detailed_info = request.form.get('collectDetailedInfo') == 'on'
        concurrency = int(request.form.get('concurrency', 10))
        template_id = request.form.get('commandTemplate', '')
        custom_commands = request.form.get('customCommands', '')
        sudo_password = request.form.get('sudoPassword', '')
        
        # Check if using credential sets
        use_credential_sets = request.form.get('use_credential_sets') == 'true'
        multiple_credentials = request.form.get('multiple_credentials') == 'true'
        credential_set_id = request.form.get('credentialSet')
    
    # Authentication info initialization
    username = None
    auth_type = None
    password = None
    private_key = None
    credential_sets_to_use = None
    
    # Handle credential sets logic
    if use_credential_sets:
        if not credential_set_id and not multiple_credentials:
            return jsonify({"error": "No credential set selected"}), 400
        
        if multiple_credentials:
            # Get all credential sets in priority order
            credential_sets_to_use = CredentialSet.query.order_by(CredentialSet.priority.desc()).all()
            if not credential_sets_to_use:
                return jsonify({"error": "No credential sets found"}), 400
        else:
            # Get single credential set
            credential_set = CredentialSet.query.get(int(credential_set_id))
            if not credential_set:
                return jsonify({"error": "Invalid credential set selected"}), 400
            credential_sets_to_use = [credential_set]
        
        # Use first credential set for scan session record
        username = credential_sets_to_use[0].username
        auth_type = credential_sets_to_use[0].auth_type
    else:
        # Get manual credentials from form/json
        if request.is_json:
            username = data.get('username', '')
            auth_type = data.get('auth_type', 'password')
            password = data.get('password', '') if auth_type == 'password' else None
            private_key = data.get('private_key', '') if auth_type == 'key' else None
        else:
            username = request.form.get('username', '')
            auth_type = request.form.get('authType', 'password')
            password = request.form.get('password', '') if auth_type == 'password' else None
            private_key = request.form.get('privateKey', '') if auth_type == 'key' else None
        
        # Validate manual credentials
        if not subnets:
            return jsonify({"error": "No subnets provided"}), 400
            
        if not username:
            return jsonify({"error": "Username is required"}), 400
        
        if auth_type == 'password' and not password:
            return jsonify({"error": "Password is required"}), 400
        
        if auth_type == 'key' and not private_key:
            return jsonify({"error": "Private key is required"}), 400
    
    # Parse subnets
    try:
        ip_addresses = parse_subnet_input(subnets)
        if not ip_addresses:
            return jsonify({"error": "No valid IP addresses found"}), 400
    except Exception as e:
        return jsonify({"error": f"Error parsing subnets: {str(e)}"}), 400
    
    # Get commands
    commands = []
    
    # From template
    if template_id and template_id != '':
        try:
            template_id_int = int(template_id)
            template = CommandTemplate.query.get(template_id_int)
            if template:
                commands = template.commands.splitlines()
        except ValueError:
            # Handle invalid template ID
            pass
    
    # From custom commands field
    if custom_commands:
        if isinstance(custom_commands, str):
            custom_cmd_list = custom_commands.splitlines()
            commands.extend([cmd.strip() for cmd in custom_cmd_list if cmd.strip()])
    
    # Create a new scan session
    scan_session = ScanSession(
        username=username,
        auth_type=auth_type,
        collect_server_info=collect_server_info,
        collect_detailed_info=collect_detailed_info
    )
    db.session.add(scan_session)
    db.session.commit()
    
    # Create initial scan results
    from models import ScanResult
    for ip in ip_addresses:
        result = ScanResult(
            scan_session_id=scan_session.id,
            ip_address=ip,
            status_code='pending'
        )
        db.session.add(result)
    
    db.session.commit()
    
    # Store session ID in session
    session['current_scan_id'] = scan_session.id
    
    # Start scan in background
    start_scan_session(
        scan_session_id=scan_session.id,
        ip_addresses=ip_addresses,
        username=username,
        password=password,
        private_key=private_key,
        commands=commands,
        collect_server_info=collect_server_info,
        collect_detailed_info=collect_detailed_info,
        sudo_password=sudo_password,
        credential_sets=credential_sets_to_use,
        concurrency=concurrency
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
    from models import ScanResult, ScanSession
    
    scan_session = ScanSession.query.get_or_404(scan_id)
    results = ScanResult.query.filter_by(scan_session_id=scan_id).all()
    
    # Calculate summary statistics
    total = len(results)
    success_count = sum(1 for r in results if r.status_code == 'success')
    failed_count = total - success_count
    
    return jsonify({
        "scan_id": scan_id,
        "session": scan_session.to_dict(),
        "results": [r.to_dict() for r in results],
        "summary": {
            "total": total,
            "success": success_count,
            "failed": failed_count,
            "success_rate": (success_count / total * 100) if total > 0 else 0
        }
    })
    
@app.route('/scan_results/<int:scan_id>/export/<format>')
def export_results(scan_id, format):
    """Export scan results in various formats (CSV, JSON, PDF)"""
    from datetime import datetime
    import csv
    import json
    from io import StringIO, BytesIO
    import pandas as pd
    import matplotlib.pyplot as plt
    from flask import Response, make_response
    from models import ScanResult, ScanSession
    
    try:
        # Get scan session and results
        scan_session = ScanSession.query.get_or_404(scan_id)
        results = ScanResult.query.filter_by(scan_session_id=scan_id).all()
        
        # Generate timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"subnet_whisperer_results_{scan_id}_{timestamp}"
        
        # Calculate summary statistics
        total = len(results)
        success_count = sum(1 for r in results if r.status_code == 'success')
        failed_count = total - success_count
        success_rate = (success_count / total * 100) if total > 0 else 0
        
        # Format based on requested format
        if format.lower() == 'csv':
            # Create CSV
            output = StringIO()
            csv_writer = csv.writer(output)
            
            # Write header
            csv_writer.writerow(['IP Address', 'Status', 'SSH Status', 'Sudo Status', 'Command Status', 
                                'Execution Time (s)', 'Error Message', 'Created At'])
            
            # Write data rows
            for result in results:
                csv_writer.writerow([
                    result.ip_address,
                    result.status_code,
                    'Yes' if result.ssh_status else 'No',
                    'Yes' if result.sudo_status else 'No',
                    'Yes' if result.command_status else 'No',
                    result.execution_time,
                    result.error_message,
                    result.created_at.strftime('%Y-%m-%d %H:%M:%S')
                ])
            
            # Create response
            response = make_response(output.getvalue())
            response.headers["Content-Disposition"] = f"attachment; filename={filename}.csv"
            response.headers["Content-type"] = "text/csv"
            return response
            
        elif format.lower() == 'json':
            # Create JSON
            export_data = {
                'scan_id': scan_id,
                'username': scan_session.username,
                'auth_type': scan_session.auth_type,
                'status': scan_session.status,
                'started_at': scan_session.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan_session.started_at else None,
                'completed_at': scan_session.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan_session.completed_at else None,
                'summary': {
                    'total': total,
                    'success': success_count,
                    'failed': failed_count,
                    'success_rate': success_rate
                },
                'results': []
            }
            
            # Add result details
            for result in results:
                export_data['results'].append({
                    'ip_address': result.ip_address,
                    'status_code': result.status_code,
                    'ssh_status': result.ssh_status,
                    'sudo_status': result.sudo_status,
                    'command_status': result.command_status,
                    'command_output': result.command_output,
                    'server_info': result.server_info,
                    'error_message': result.error_message,
                    'execution_time': result.execution_time,
                    'created_at': result.created_at.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            # Create response
            response = make_response(json.dumps(export_data, indent=2))
            response.headers["Content-Disposition"] = f"attachment; filename={filename}.json"
            response.headers["Content-type"] = "application/json"
            return response
            
        elif format.lower() == 'pdf':
            # Create PDF report using matplotlib and pandas
            buffer = BytesIO()
            
            # Create a pandas dataframe for the results table
            data = {
                'IP Address': [r.ip_address for r in results],
                'Status': [r.status_code for r in results],
                'SSH Status': ['Yes' if r.ssh_status else 'No' for r in results],
                'Command Status': ['Yes' if r.command_status else 'No' for r in results],
                'Execution Time (s)': [r.execution_time for r in results],
            }
            df = pd.DataFrame(data)
            
            # Create a summary figure
            plt.figure(figsize=(11, 8))
            
            # Add a title with scan information
            plt.suptitle(f'Subnet Whisperer Scan Results (ID: {scan_id})', fontsize=16)
            plt.figtext(0.1, 0.92, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            plt.figtext(0.1, 0.90, f'Username: {scan_session.username}')
            plt.figtext(0.1, 0.88, f'Authentication: {scan_session.auth_type}')
            plt.figtext(0.1, 0.86, f'Started: {scan_session.started_at.strftime("%Y-%m-%d %H:%M:%S") if scan_session.started_at else "N/A"}')
            plt.figtext(0.1, 0.84, f'Completed: {scan_session.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan_session.completed_at else "N/A"}')
            
            # Add success/fail chart
            plt.subplot(2, 2, 1)
            plt.pie([success_count, failed_count], labels=['Success', 'Failed'], 
                    autopct='%1.1f%%', colors=['#28a745', '#dc3545'])
            plt.title('Scan Results')
            
            # Add status codes breakdown if we have successful results
            status_categories = {}
            for r in results:
                if r.status_code not in status_categories:
                    status_categories[r.status_code] = 0
                status_categories[r.status_code] += 1
            
            plt.subplot(2, 2, 2)
            if status_categories:
                plt.bar(status_categories.keys(), status_categories.values())
                plt.title('Status Breakdown')
                plt.xticks(rotation=45)
            
            # Add results table
            plt.subplot(2, 1, 2)
            plt.axis('off')
            if not df.empty:
                table = plt.table(
                    cellText=df.values[:20],  # Show only first 20 rows
                    colLabels=df.columns,
                    loc='center',
                    cellLoc='center',
                )
                table.auto_set_font_size(False)
                table.set_fontsize(8)
                table.scale(1, 1.5)
                plt.title('Scan Results (First 20 rows)')
                
                if len(df) > 20:
                    plt.figtext(0.5, 0.25, f'... and {len(df) - 20} more results', 
                             ha='center', fontsize=8, style='italic')
            
            # Save figure to buffer
            plt.tight_layout(rect=[0, 0, 1, 0.8])
            plt.savefig(buffer, format='pdf')
            buffer.seek(0)
            
            # Create response
            response = make_response(buffer.getvalue())
            response.headers["Content-Disposition"] = f"attachment; filename={filename}.pdf"
            response.headers["Content-type"] = "application/pdf"
            return response
            
        else:
            return jsonify({'error': 'Unsupported export format'}), 400
            
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

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

@app.route('/schedules')
def schedules():
    from models import ScheduledScan, ScanSession
    import sqlalchemy
    
    scheduled_scans = ScheduledScan.query.order_by(ScheduledScan.created_at.desc()).all()
    
    # Get recent scan sessions from scheduled scans
    recent_sessions = []
    try:
        # Since there may not be scheduled scans yet, just get regular scan sessions
        recent_sessions_query = """
        SELECT s.id, s.username, s.started_at, s.status, 'Manual Scan' as schedule_name 
        FROM scan_sessions s
        ORDER BY s.started_at DESC
        LIMIT 10
        """
        from sqlalchemy import text
        with db.engine.connect() as conn:
            result = conn.execute(text(recent_sessions_query))
            recent_sessions = [dict(row) for row in result]
    except Exception as e:
        logger.error(f"Error fetching recent scheduled scan sessions: {str(e)}")
    
    return render_template('schedules.html', scheduled_scans=scheduled_scans, recent_sessions=recent_sessions)

@app.route('/schedules/create', methods=['GET', 'POST'])
def create_schedule():
    from forms import ScheduledScanForm
    from models import CommandTemplate, ScheduledScan
    from datetime import datetime
    from encryption_utils import encrypt_data
    
    form = ScheduledScanForm()
    
    # Populate template choices
    templates = CommandTemplate.query.all()
    form.command_template.choices = [(0, 'None')] + [(t.id, t.name) for t in templates]
    
    if form.validate_on_submit():
        # Process form data
        password_encrypted = None
        private_key_encrypted = None
        
        # Use proper encryption
        if form.auth_type.data == 'password' and form.password.data:
            password_encrypted = encrypt_data(form.password.data)
        elif form.auth_type.data == 'key' and form.private_key.data:
            private_key_encrypted = encrypt_data(form.private_key.data)
        
        # Create scheduled scan
        scheduled_scan = ScheduledScan(
            name=form.name.data,
            description=form.description.data,
            subnets=form.subnets.data,
            username=form.username.data,
            auth_type=form.auth_type.data,
            password_encrypted=password_encrypted,
            private_key_encrypted=private_key_encrypted,
            command_template_id=form.command_template.data if form.command_template.data != 0 else None,
            custom_commands=form.custom_commands.data,
            collect_server_info=form.collect_server_info.data,
            collect_detailed_info=form.collect_detailed_info.data,
            concurrency=form.concurrency.data,
            schedule_frequency=form.schedule_frequency.data,
            custom_interval_minutes=form.custom_interval_minutes.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            is_active=form.is_active.data
        )
        
        # Calculate next run time
        scheduled_scan.next_run = scheduled_scan.calculate_next_run()
        
        db.session.add(scheduled_scan)
        db.session.commit()
        
        flash('Scheduled scan created successfully!', 'success')
        return redirect(url_for('schedules'))
    
    # Set default values
    if not form.start_date.data:
        form.start_date.data = datetime.utcnow()
    
    return render_template('schedule_form.html', form=form, schedule=None)

@app.route('/schedules/<int:schedule_id>', methods=['GET'])
def view_schedule(schedule_id):
    from models import ScheduledScan
    
    scheduled_scan = ScheduledScan.query.get_or_404(schedule_id)
    return render_template('schedule_detail.html', schedule=scheduled_scan)

@app.route('/schedules/<int:schedule_id>/edit', methods=['GET', 'POST'])
def edit_schedule(schedule_id):
    from forms import ScheduledScanForm
    from models import ScheduledScan, CommandTemplate
    from encryption_utils import encrypt_data
    
    scheduled_scan = ScheduledScan.query.get_or_404(schedule_id)
    form = ScheduledScanForm(obj=scheduled_scan)
    
    # Populate template choices
    templates = CommandTemplate.query.all()
    form.command_template.choices = [(0, 'None')] + [(t.id, t.name) for t in templates]
    
    if form.validate_on_submit():
        # Update scheduled scan from form
        scheduled_scan.name = form.name.data
        scheduled_scan.description = form.description.data
        scheduled_scan.subnets = form.subnets.data
        scheduled_scan.username = form.username.data
        scheduled_scan.auth_type = form.auth_type.data
        scheduled_scan.command_template_id = form.command_template.data if form.command_template.data != 0 else None
        scheduled_scan.custom_commands = form.custom_commands.data
        scheduled_scan.collect_server_info = form.collect_server_info.data
        scheduled_scan.collect_detailed_info = form.collect_detailed_info.data
        scheduled_scan.concurrency = form.concurrency.data
        scheduled_scan.schedule_frequency = form.schedule_frequency.data
        scheduled_scan.custom_interval_minutes = form.custom_interval_minutes.data
        scheduled_scan.start_date = form.start_date.data
        scheduled_scan.end_date = form.end_date.data
        scheduled_scan.is_active = form.is_active.data
        
        # Handle password/key updates
        keep_existing_password = request.form.get('keep_existing_password') == 'on'
        keep_existing_key = request.form.get('keep_existing_key') == 'on'
        
        if form.auth_type.data == 'password' and not keep_existing_password and form.password.data:
            scheduled_scan.password_encrypted = encrypt_data(form.password.data)
        elif form.auth_type.data == 'key' and not keep_existing_key and form.private_key.data:
            scheduled_scan.private_key_encrypted = encrypt_data(form.private_key.data)
        
        # Recalculate next run time
        scheduled_scan.next_run = scheduled_scan.calculate_next_run()
        
        db.session.commit()
        flash('Scheduled scan updated successfully!', 'success')
        return redirect(url_for('schedules'))
    
    # Add property to check if private key exists
    scheduled_scan.has_private_key = bool(scheduled_scan.private_key_encrypted)
    
    return render_template('schedule_form.html', form=form, schedule=scheduled_scan)

@app.route('/schedules/<int:schedule_id>/activate', methods=['POST'])
def activate_schedule(schedule_id):
    from models import ScheduledScan
    
    scheduled_scan = ScheduledScan.query.get_or_404(schedule_id)
    scheduled_scan.is_active = True
    scheduled_scan.next_run = scheduled_scan.calculate_next_run()
    db.session.commit()
    
    return jsonify({
        "success": True,
        "message": f"Schedule '{scheduled_scan.name}' activated successfully"
    })

@app.route('/schedules/<int:schedule_id>/deactivate', methods=['POST'])
def deactivate_schedule(schedule_id):
    from models import ScheduledScan
    
    scheduled_scan = ScheduledScan.query.get_or_404(schedule_id)
    scheduled_scan.is_active = False
    db.session.commit()
    
    return jsonify({
        "success": True,
        "message": f"Schedule '{scheduled_scan.name}' deactivated successfully"
    })

@app.route('/schedules/<int:schedule_id>/delete', methods=['POST'])
def delete_schedule(schedule_id):
    from models import ScheduledScan
    
    scheduled_scan = ScheduledScan.query.get_or_404(schedule_id)
    db.session.delete(scheduled_scan)
    db.session.commit()
    
    return jsonify({
        "success": True,
        "message": f"Schedule '{scheduled_scan.name}' deleted successfully"
    })

@app.route('/credentials', methods=['GET', 'POST'])
def credentials():
    from forms import CredentialSetForm
    from models import CredentialSet
    from encryption_utils import encrypt_data
    
    form = CredentialSetForm()
    credential_sets = CredentialSet.query.order_by(CredentialSet.priority.desc()).all()
    
    if form.validate_on_submit():
        # Create new credential set
        credential_set = CredentialSet(
            username=form.username.data,
            auth_type=form.auth_type.data,
            description=form.description.data,
            priority=form.priority.data
        )
        
        # Use proper encryption
        if form.auth_type.data == 'password' and form.password.data:
            credential_set.password_encrypted = encrypt_data(form.password.data)
        elif form.auth_type.data == 'key' and form.private_key.data:
            credential_set.private_key_encrypted = encrypt_data(form.private_key.data)
        
        # Sudo password (optional)
        if form.sudo_password.data:
            credential_set.sudo_password_encrypted = encrypt_data(form.sudo_password.data)
        
        db.session.add(credential_set)
        db.session.commit()
        
        flash('Credential set created successfully!', 'success')
        return redirect(url_for('credentials'))
    
    return render_template('credentials.html', form=form, credential_sets=credential_sets)

@app.route('/add_credential', methods=['POST'])
def add_credential():
    from forms import CredentialSetForm
    from models import CredentialSet
    from encryption_utils import encrypt_data
    
    form = CredentialSetForm()
    
    if form.validate_on_submit():
        # Create new credential set
        credential_set = CredentialSet(
            username=form.username.data,
            auth_type=form.auth_type.data,
            description=form.description.data,
            priority=form.priority.data
        )
        
        # Use proper encryption
        if form.auth_type.data == 'password' and form.password.data:
            credential_set.password_encrypted = encrypt_data(form.password.data)
        elif form.auth_type.data == 'key' and form.private_key.data:
            credential_set.private_key_encrypted = encrypt_data(form.private_key.data)
        
        # Sudo password (optional)
        if form.sudo_password.data:
            credential_set.sudo_password_encrypted = encrypt_data(form.sudo_password.data)
        
        db.session.add(credential_set)
        db.session.commit()
        
        flash('Credential set created successfully!', 'success')
    else:
        flash('Error creating credential set: ' + str(form.errors), 'danger')
    
    return redirect(url_for('credentials'))

@app.route('/edit_credential', methods=['POST'])
def edit_credential():
    from forms import CredentialSetForm
    from models import CredentialSet
    from encryption_utils import encrypt_data
    
    form = CredentialSetForm()
    
    if form.validate_on_submit():
        credential_set = CredentialSet.query.get_or_404(form.id.data)
        
        # Update basic info
        credential_set.username = form.username.data
        credential_set.auth_type = form.auth_type.data
        credential_set.description = form.description.data
        credential_set.priority = form.priority.data
        
        # Update passwords/keys only if provided (not empty)
        if form.auth_type.data == 'password' and form.password.data:
            credential_set.password_encrypted = encrypt_data(form.password.data)
            credential_set.private_key_encrypted = None  # Clear the key if switching to password
        elif form.auth_type.data == 'key' and form.private_key.data:
            credential_set.private_key_encrypted = encrypt_data(form.private_key.data)
            credential_set.password_encrypted = None  # Clear the password if switching to key
        
        # Update sudo password if provided
        if form.sudo_password.data:
            credential_set.sudo_password_encrypted = encrypt_data(form.sudo_password.data)
        
        db.session.commit()
        flash('Credential set updated successfully!', 'success')
    else:
        flash('Error updating credential set: ' + str(form.errors), 'danger')
    
    return redirect(url_for('credentials'))

@app.route('/delete_credential', methods=['POST'])
def delete_credential():
    from models import CredentialSet
    
    credential_id = request.form.get('credential_id')
    credential_set = CredentialSet.query.get_or_404(credential_id)
    
    db.session.delete(credential_set)
    db.session.commit()
    
    flash('Credential set deleted successfully!', 'success')
    return redirect(url_for('credentials'))

@app.route('/credential/<int:credential_id>')
def get_credential(credential_id):
    from models import CredentialSet
    
    credential_set = CredentialSet.query.get_or_404(credential_id)
    return jsonify(credential_set.to_dict())

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500
