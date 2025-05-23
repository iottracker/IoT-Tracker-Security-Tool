from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import re
import subprocess
import requests
import magic
import base64
import json
import pandas as pd
import os
import uuid
import nmap
import ipaddress
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Union
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
from fpdf import FPDF
import functools
from IoTscanner5 import (
    scan_network, scan_port, scan_ports, get_manufacturer, analyze_http_headers,
    directory_enumeration, test_sql_injection, test_xss, get_cve_details_from_circl_web, scan_https_issues,
    scan_services_for_issues, generate_html_report,
    get_device_details, generate_recommendations, save_recommendations_to_file,
    save_to_html, save_to_csv, scan_vulnerabilities, analyze_traffic
)
import time
import shutil
import zipfile
import io
from werkzeug.utils import secure_filename
from func_timeout import func_timeout, FunctionTimedOut
import psutil
import sys
import os
import re
import uuid
import time
import shutil
import magic
import logging
import zipfile
import io
import threading
import subprocess
import cachetools
import requests
import psutil
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from typing import List, Dict, Tuple, Optional, Any
import fnmatch
from flask import send_from_directory
from attack_cve_parser import parse_attack_cve_file
from docker import from_env as docker_from_env
import docker
from typing import List, Dict
import tempfile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log", encoding='utf-8'),  # Add encoding
        logging.StreamHandler(stream=sys.stderr)  # Use stderr with UTF-8
    ]
)
logger = logging.getLogger(__name__)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Environment variables
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-secret-key')
DATABASE_URI = os.environ.get('DATABASE_URI', 'sqlite:///users.db')
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
SCANS_FOLDER = os.environ.get('SCANS_FOLDER', 'scans')

# Ensure directories exist
for folder in [UPLOAD_FOLDER, SCANS_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Initialize Flask app
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500MB max upload
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    SCANS_FOLDER=SCANS_FOLDER
)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
ATTACK_CVE_FILE = os.path.join(APP_ROOT, 'data', 'attack_cve_mappings.txt')

try:
    attack_cve_map = parse_attack_cve_file(ATTACK_CVE_FILE)
    logger.info(f"Successfully loaded attack-CVE mappings with {len(attack_cve_map)} attack types")
except Exception as e:
    logger.error(f"Failed to load attack-CVE mappings: {str(e)}", exc_info=True)
    attack_cve_map = {}

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate(app, db)
# Create the limiter with enabled=False
limiter = Limiter(
    app=app,  # Make sure to use app=app instead of just app
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    enabled=False  # This disables the limiter
)

cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    security_question = db.Column(db.String(200), nullable=False)
    security_answer = db.Column(db.String(200), nullable=False)
    account_alerts_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def get_id(self) -> str:
        return str(self.id)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User.query.get(int(user_id))

# Create the database and tables
with app.app_context():
    db.create_all()

# Background task management
background_tasks: Dict[str, Dict[str, Any]] = {}
task_lock = threading.Lock()

@app.route('/guest_login')
def guest_login():
    session.clear()
    session['username'] = 'Guest'
    return redirect(url_for('dashboard'))


# Password validation function
def is_password_valid(password: str) -> Tuple[bool, str]:
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    return True, "Password is valid."

# Email validation function
def is_email_valid(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

# IP validation function
def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Decorator for routes that require guest access
def guest_or_login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated or session.get('username') == 'Guest':
            return f(*args, **kwargs)
        return redirect(url_for('login'))
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/getstarted')
def getstarted():
    return render_template('getstarted.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        remember_me = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember_me)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            session['username'] = user.username
            
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
            logger.warning(f"Failed login attempt for email: {email}")

    return render_template('login.html')

@app.route('/dashboard')
@guest_or_login_required
def dashboard():
    # Check if the user is accessing as a guest
    if session.get('username') == 'Guest':
        return render_template('dashboard.html', username='Guest')

    # If not a guest, use the current_user
    if current_user.is_authenticated:
        return render_template('dashboard.html', username=current_user.username, email=current_user.email)
    
    # If not authenticated and not guest, redirect to login
    return redirect(url_for('login'))


@app.route('/logout', methods=['POST'])
def logout():
    if current_user.is_authenticated:
        logout_user()
    
    session.clear()
    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie('user_id')
    return resp

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '')
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        security_question = request.form.get('security_question', '')
        security_answer = request.form.get('security_answer', '')

        # Validate email format
        if not is_email_valid(email):
            flash('Invalid email format. Please enter a valid email address.', 'error')
            return redirect(url_for('register'))

        # Check if the email already exists
        if User.query.filter_by(email=email).first():
            flash('This email is already registered. Please use a different email.', 'error')
            return redirect(url_for('register'))

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            flash('This username is already taken. Please choose a different username.', 'error')
            return redirect(url_for('register'))

        # Validate the password
        is_valid, message = is_password_valid(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('register'))

        # Hash the password and security answer
        hashed_password = generate_password_hash(password)
        hashed_security_answer = generate_password_hash(security_answer)

        # Create a new user
        new_user = User(
            email=email,
            username=username,
            password=hashed_password,
            security_question=security_question,
            security_answer=hashed_security_answer
        )
        db.session.add(new_user)
        db.session.commit()

        logger.info(f"New user registered: {username}")
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '')
        user = User.query.filter_by(email=email).first()
        if user:
            # Use a token instead of exposing email in URL
            token = str(uuid.uuid4())
            cache.set(f"reset_token_{token}", email, timeout=3600)  # 1 hour expiry
            return redirect(url_for('security_question', token=token))
        else:
            flash('No account found with this email address.', 'error')
    return render_template('forgot_password.html')

@app.route('/security-question/<token>', methods=['GET', 'POST'])
def security_question(token):
    email = cache.get(f"reset_token_{token}")
    if not email:
        flash('Invalid or expired token. Please try again.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        security_answer = request.form.get('security_answer', '')
        if check_password_hash(user.security_answer, security_answer):
            # Generate a new token for password reset
            reset_token = str(uuid.uuid4())
            cache.set(f"password_reset_{reset_token}", email, timeout=1800)  # 30 minutes expiry
            return redirect(url_for('reset_password', token=reset_token))
        else:
            flash('Incorrect security answer.', 'error')

    return render_template('security_question.html', security_question=user.security_question, token=token)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = cache.get(f"password_reset_{token}")
    if not email:
        flash('Invalid or expired token. Please try again.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        is_valid, message = is_password_valid(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('reset_password', token=token))

        hashed_password = generate_password_hash(password)
        user.password = hashed_password
        db.session.commit()

        # Clear the token
        cache.delete(f"password_reset_{token}")
        
        logger.info(f"Password reset for user: {user.username}")
        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)



@app.route('/explorer')
@guest_or_login_required
def explorer():
    username = session.get('username')
    return render_template('explorer.html', username=username)


def check_device_status(ip: str) -> str:
    """Check if a device is online using ping"""
    try:
        # Windows compatibility
        ping_args = ['-n', '1', '-w', '1000'] if os.name == 'nt' else ['-c', '1', '-W', '1']
        subprocess.check_output(
            ['ping', *ping_args, ip],
            stderr=subprocess.STDOUT,
            timeout=2
        )
        return "online"
    except Exception:
        return "offline"

def list_docker_containers() -> List[Dict[str, str]]:
    containers = []
    try:
        client = docker.from_env()
        for container in client.containers.list():
            info = container.attrs
            networks = info.get("NetworkSettings", {}).get("Networks", {})
            ip_address = "N/A"

            # Grab the IP address from the first available network
            if networks:
                ip_address = list(networks.values())[0].get("IPAddress", "N/A")

            containers.append({
                "name": container.name,
                "id": container.id[:12],
                "image": info["Config"].get("Image", "unknown"),
                "ip": ip_address,
                "status": container.status,
                "open_ports": info.get("NetworkSettings", {}).get("Ports", {})
            })
    except Exception as e:
        logger.error(f"Docker container listing failed: {str(e)}")
    return containers

@app.route('/scan', methods=['GET', 'POST'])
@guest_or_login_required
def scan():
    username = session.get('username')
    is_guest = username == 'Guest'

    if request.method == 'GET':
        return render_template('scan.html', username=username or 'Guest')

    try:
        # Handle JSON or form POST
        if request.is_json:
            data = request.get_json(force=True)
            network = data.get('network')
        else:
            network = request.form.get('network')

        if not network:
            error_msg = "No network range provided"
            if request.is_json:
                return jsonify({"error": error_msg}), 400
            flash(error_msg, 'error')
            return redirect(url_for('scan'))

        # Network device scan
        devices = scan_network(network)
        processed_devices = [{
            "ip": device.get('ip', 'Unknown IP'),
            "mac": device.get('mac', 'Unknown MAC'),
            "manufacturer": get_manufacturer(device.get('mac', '')),
            "open_ports": scan_ports(device.get('ip', '')),
            "status": check_device_status(device.get('ip', ''))
        } for device in devices]

        # Return results
        if request.is_json:
            return jsonify({
                "devices": processed_devices,
            })

        return render_template(
            'scan.html',
            username=username or 'Guest',
            devices=processed_devices,
            show_loading=False,
            show_info=True
        )

    except Exception as e:
        logger.error(f"Scan error: {str(e)}", exc_info=True)
        error_msg = f"Scan error: {str(e)}"
        if request.is_json:
            return jsonify({"error": error_msg}), 500
        flash(error_msg, 'error')
        return redirect(url_for('scan'))

    
@app.route('/docker_scan')
@guest_or_login_required
def docker_scan():
    username = session.get('username')
    docker_containers = list_docker_containers()
    return render_template(
        'scan.html',
        username=username or 'Guest',
        containers=docker_containers
    )

    

@app.route('/scan_vulns', methods=['GET', 'POST'])
@login_required
def scan_vulns():
    html_report = None
    recommendations = None
    scan_error = None
    scan_type = None

    if request.method == 'POST':
        scan_type = request.form.get('scan_type', 'ip')
        target = request.form.get('target', '').strip()
        
        if scan_type == 'ip':
            # Validate IP
            if not is_valid_ip(target):
                flash('Invalid IP address format', 'error')
                return redirect(url_for('scan_vulns'))

            # Check for existing active scan
            current_task_id = session.get('scan_task_id')
            if current_task_id and background_tasks.get(current_task_id, {}).get('status') in ['queued', 'scanning']:
                flash('Another scan is already in progress', 'error')
                return redirect(url_for('scan_vulns'))

            # Clear previous scan
            if 'scan_task_id' in session:
                old_id = session.pop('scan_task_id')
                with task_lock:
                    background_tasks.pop(old_id, None)

            try:
                # Start background scan
                task_id = str(uuid.uuid4())
                with task_lock:
                    background_tasks[task_id] = {
                        'status': 'queued',
                        'start_time': datetime.now().isoformat(),
                        'target': target,
                        'progress': 0
                    }
                session['scan_task_id'] = task_id
                session.modified = True

                # Start background thread for comprehensive scan
                threading.Thread(target=run_background_scan, args=(target, task_id)).start()

                # Run quick scans in foreground
                http_results = analyze_http_headers(target)
                dir_enum_results = directory_enumeration(target)
                sql_results = test_sql_injection(target)
                xss_results = test_xss(target)
                https_results = scan_https_issues(target)

                # Generate immediate report
                vuln_results = scan_vulnerabilities(target)
                html_report = generate_html_report(vuln_results, [
                    http_results,
                    dir_enum_results,
                    sql_results,
                    xss_results,
                    https_results
                ])

                open_ports = scan_ports(target)
                recommendations = generate_recommendations(vuln_results, open_ports) or \
                    "<div class='no-recommendations'>No specific recommendations available</div>"

                flash('Initial results ready. Comprehensive scan running in background.', 'success')

            except Exception as e:
                logger.error(f"Scan error for {target}: {str(e)}", exc_info=True)
                scan_error = str(e)
                flash(f'Scan error: {scan_error}', 'error')

        elif scan_type == 'docker':
            # Container scan logic remains the same
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]+$', target):
                flash('Invalid container name format', 'error')
                return redirect(url_for('scan_vulns'))

            try:
                html_report, recommendations, scan_error = run_container_scan(target)
                if scan_error:
                    flash(f'Container scan error: {scan_error}', 'error')
            except Exception as e:
                logger.error(f"Container scan failed: {str(e)}", exc_info=True)
                flash('Failed to scan container', 'error')

    return render_template(
        'scan_vulns.html',
        username=current_user.username,
        html_report=html_report,
        recommendations=recommendations,
        scan_error=scan_error,
        scan_type=scan_type
    )


def run_dockle_scan(image_name):
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', '-v', '/var/run/docker.sock:/var/run/docker.sock',
             'goodwithtech/dockle', image_name],
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Dockle scan failed: {str(e)}"

def run_snyk_scan(image_name):
    """
    Run Snyk container scan using personal API token authentication
    """
    try:
        # 1. Configuration paths - Update these to match your Windows environment
        snyk_path = r'C:\Users\janaq\AppData\Roaming\npm\snyk.cmd'
        # Use environment variable for token with fallback (WARNING: Remove hardcoded token in production)
        snyk_token = os.getenv('SNYK_TOKEN')
        
        # 2. Set up environment with proper PATH
        env = os.environ.copy()
        env['PATH'] = r'C:\Users\janaq\AppData\Roaming\npm;' + env['PATH']
        
        # 3. Configure Snyk using personal token
        if snyk_token:
            config_cmd = [
                snyk_path,
                'config',
                'set',
                f'api={snyk_token}'
            ]
            
            config_result = subprocess.run(
                config_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15,
                env=env
            )
            
            if config_result.returncode != 0:
                logger.error(f"Snyk Config Failed: {config_result.stderr}")
                return {"error": "Snyk configuration failed", "details": config_result.stderr}
        else:
            logger.warning("SNYK_TOKEN environment variable not set")
            return {"error": "Snyk API token not configured"}

        # 4. Run container scan
        scan_cmd = [
            snyk_path,
            'container',
            'test',
            image_name,
            '--json'
        ]
        
        result = subprocess.run(
            scan_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
            env=env
        )

        # 5. Handle output
        if result.returncode in [0, 1]:  # Valid success/vulnerability states
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"error": "Invalid JSON output", "output": result.stdout[:200]}
                
        return {"error": f"Snyk error (code {result.returncode})", "details": result.stderr}

    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 2 minutes"}
    except Exception as e:
        logger.error(f"Snyk Error: {str(e)}")
        return {"error": "Scan failed", "details": str(e)}



# New function to run container scan using Trivy
def run_container_scan(container_name):
    try:
        # 1. Run Trivy scan first
        temp_output_file = os.path.join(tempfile.gettempdir(), "trivy_scan.json")
        trivy_command = [
            "trivy", "image", "--format", "json", "--output", temp_output_file,
            "--security-checks", "vuln,secret", container_name
        ]
        subprocess.run(trivy_command, capture_output=True, text=True, timeout=120)

        with open(temp_output_file, "r", encoding="utf-8") as f:
            trivy_data = json.load(f)
        os.remove(temp_output_file)

        # 2. Process Trivy results first to initialize 'combined'
        combined = process_trivy_results(trivy_data)

        # 3. Run Dockle scan
        combined["dockle"] = run_dockle_scan(container_name)

        # 4. Run Snyk scan
        snyk_output = run_snyk_scan(container_name)
        if 'error' in snyk_output:
            combined['snyk'] = {"error": snyk_output['error']}
        else:
            combined['snyk'] = process_snyk_results(snyk_output)

        # 5. Generate final output
        html_report = generate_container_html_report(combined)
        recommendations = generate_container_recommendations(combined)

        return html_report, recommendations, None

    except Exception as e:
        logger.error(f"Container scan error: {str(e)}", exc_info=True)
        return None, None, str(e)
    

def process_snyk_results(snyk_data):
    """
    Transform Snyk output into a structured report format
    with better categorization and styling options
    """
    # Initialize structured data
    result = {
        'vulnerabilities': [],
        'summary': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0
        },
        'affected_packages': set(),
        'fixable_count': 0
    }
    
    # Process vulnerability data
    if 'vulnerabilities' in snyk_data:
        # Map and transform each vulnerability
        for v in snyk_data.get('vulnerabilities', []):
            severity = v.get('severity', 'unknown').lower()
            
            # Update summary counts
            result['summary'][severity] = result['summary'].get(severity, 0) + 1
            
            # Track affected packages
            package_name = v.get('package', {}).get('name') or v.get('packageName') or v.get('package_name', 'Unknown')
            result['affected_packages'].add(package_name)
            
            # Check if fixable
            if v.get('fixedIn') or v.get('fixed_version') or v.get('isFixable'):
                result['fixable_count'] += 1
            
            # Add structured vulnerability information
            structured_vuln = {
                'id': v.get('id') or v.get('vulnerabilityId') or v.get('vulnerability_id', 'Unknown'),
                'title': v.get('title', ''),
                'severity': severity,
                'package_name': package_name,
                'installed_version': v.get('version') or v.get('packageVersion') or v.get('installed_version', 'Unknown'),
                'fixed_version': v.get('fixedIn') or v.get('fixed_version', 'Not available'),
                'cves': v.get('identifiers', {}).get('CVE', []) if isinstance(v.get('identifiers', {}), dict) else [],
                'cvss_score': v.get('cvssScore') or v.get('cvss', {}).get('score') or v.get('cvssv3_score', 0),
                'description': v.get('description', ''),
                'paths': v.get('from', [])[:5] if isinstance(v.get('from', []), list) else [],
                'exploit_maturity': v.get('exploitMaturity', 'Unknown'),
                'url': v.get('url', '')
            }
            result['vulnerabilities'].append(structured_vuln)
    
    # Convert affected_packages set to list for JSON serialization
    result['affected_packages'] = list(result['affected_packages'])
    result['total_vulnerabilities'] = sum(result['summary'].values())
    
    return result


# Helper function to get basic container info
def get_basic_container_info(container_name):
    try:
        # Use docker command to get basic info about the container/image
        command = ["docker", "image", "inspect", container_name]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            return {"error": "Unable to get container information"}
        
        # Parse the output
        image_info = json.loads(stdout.decode('utf-8'))
        
        # Extract relevant info
        if image_info and len(image_info) > 0:
            info = image_info[0]
            return {
                "id": info.get("Id", "Unknown"),
                "created": info.get("Created", "Unknown"),
                "size": info.get("Size", 0),
                "tags": info.get("RepoTags", []),
                "architecture": info.get("Architecture", "Unknown"),
                "os": info.get("Os", "Unknown")
            }
        return {"error": "No container information available"}
    except Exception as e:
        logger.error(f"Error getting container info: {str(e)}")
        return {"error": f"Error: {str(e)}"}

# Process Trivy scan results
def process_trivy_results(scan_data):
    results = {
        "container_info": {
            "name": scan_data.get("ArtifactName", "Unknown"),
            "type": scan_data.get("ArtifactType", "Unknown"),
            "metadata": scan_data.get("Metadata", {})
        },
        "vulnerabilities": [],
        "secrets": []
    }

    for result in scan_data.get("Results", []):
        target = result.get("Target", "Unknown")
        result_type = result.get("Type", "unknown")

        # 1. CVE-based vulnerabilities
        if result_type in ["library", "os-pkgs", "ubuntu", "debian"]:
            for vuln in result.get("Vulnerabilities", []):
                results["vulnerabilities"].append({
                    "target": target,
                    "vulnerability_id": vuln.get("VulnerabilityID", "Unknown"),
                    "package_name": vuln.get("PkgName", "Unknown"),
                    "installed_version": vuln.get("InstalledVersion", "Unknown"),
                    "fixed_version": vuln.get("FixedVersion", "Not available"),
                    "severity": vuln.get("Severity", "Unknown"),
                    "description": vuln.get("Description", "No description available"),
                    "references": vuln.get("References", [])
                })

        # 2. Secrets (from Misconfigurations)
        elif result_type in ["secret", "text", "config"]:
            # Ensure the key matches Trivy's JSON output (e.g., "Secrets" vs "secrets")
            secrets = result.get("Secrets", [])  # Adjust case if necessary
            for secret in secrets:
                results["secrets"].append({
                    "target": target,
                    "severity": secret.get("Severity", "Unknown"),
                    "category": secret.get("RuleID", "Unknown"),
                    "title": secret.get("Title", "Secret Found"),
                    "match": secret.get("Match", ""),
                    "start_line": secret.get("StartLine", "N/A"),
                    "end_line": secret.get("EndLine", "N/A")
                })
            # Debug: Print secrets found
            print(f"Found {len(secrets)} secrets in {target}")   


    return results


ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def strip_ansi(text):
    """Remove ANSI escape codes from text with type checking."""
    if text is None:
        return ""
    try:
        return ansi_escape.sub('', str(text))
    except Exception as e:
        print(f"Error stripping ANSI codes: {e}")
        return str(text)

def parse_dockle_results(dockle_output):
    """Parse Dockle output into a structured format"""
    if not dockle_output or "Dockle scan failed" in dockle_output:
        return {"error": dockle_output}
    
    results = {
        "issues": [],
        "summary": {
            "fatal": 0,
            "warn": 0,
            "info": 0,
            "pass": 0
        }
    }
    
    lines = dockle_output.strip().split('\n')
    current_issue = None
    
    for line in lines:
        line = strip_ansi(line.strip())  # Strip ANSI codes and whitespace
        if not line:
            continue
            
        # Check for level and code pattern
        if any(level in line for level in ["FATAL", "WARN", "INFO", "PASS"]):
            if current_issue:
                results["issues"].append(current_issue)
                results["summary"][current_issue["level"].lower()] += 1
            
            level = None
            if "FATAL" in line:
                level = "fatal"
            elif "WARN" in line:
                level = "warn"
            elif "INFO" in line:
                level = "info"
            elif "PASS" in line:
                level = "pass"
            
            parts = line.split(' - ', 1)
            if len(parts) == 2:
                code_part = parts[0].strip()
                title_part = parts[1].strip()
                
                code = code_part.split()[-1] if len(code_part.split()) > 1 else code_part
                
                current_issue = {
                    "level": level,
                    "code": code,
                    "title": title_part,
                    "messages": []
                }
            else:
                current_issue = {
                    "level": level,
                    "code": "",
                    "title": line,
                    "messages": []
                }
        
        elif line.startswith('*') and current_issue:
            current_issue["messages"].append(line[1:].strip())
    
    if current_issue:
        results["issues"].append(current_issue)
        results["summary"][current_issue["level"].lower()] += 1
    
    return results

def enhance_dockle_reporting(container_data):
    """Process and enhance Dockle reporting section"""
    dockle_output = container_data.get("dockle", "")
    clean_dockle_output = strip_ansi(dockle_output)  # Clean ANSI codes before parsing
    dockle_data = parse_dockle_results(clean_dockle_output)

    if "error" in dockle_data:
        return f"<div class='dockle-error'>{dockle_data['error']}</div>"

    html = """
    <div class="section-header" id="dockle-header" onclick="toggleSection(this)" data-content="dockle-content">
        <div>
            <i class="fas fa-clipboard-check"></i> Docker Best Practices Analysis
        </div>
        <i class="fas fa-chevron-down dropdown-arrow"></i>
    </div>
    <div class="section-content" id="dockle-content">
    """

    # Summary section
    html += "<div class='dockle-summary'>"
    for level, count in dockle_data["summary"].items():
        level_label = level.capitalize()
        html += f"""
        <div class='dockle-summary-item'>
            <div class='dockle-summary-title'>{level_label}</div>
            <div class='dockle-summary-value {level}'>{count}</div>
        </div>
        """
    html += "</div>"

    # Issues section
    if dockle_data["issues"]:
        for i, issue in enumerate(dockle_data["issues"]):
            issue_id = f"dockle_issue_{i}"
            level = issue["level"]

            html += f"""
            <div class='dockle-issue {level}'>
                <div class='dockle-issue-header' onclick="toggleDetails('{issue_id}_details', document.getElementById('{issue_id}_toggle'))">
                    <div style="display: flex; align-items: center;">
                        <div class='dockle-issue-code'>{issue["code"]}</div>
                        <div class='dockle-issue-title'>{issue["title"]}</div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.75rem;">
                        <div class='dockle-issue-level'>{level.upper()}</div>
                        <button id="{issue_id}_toggle" class="toggle-details-btn">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                </div>
                <div id="{issue_id}_details" class='dockle-issue-details' style='display: none;'>
            """

            if issue["messages"]:
                html += "<div class='dockle-message'>"
                for msg in issue["messages"]:
                    html += f"{msg}<br>"
                html += "</div>"

            html += "</div></div>"

    # Raw output section
    html += """
    <div style="margin-top: 1.5rem;">
        <button class="read-more-btn" onclick="toggleDetails('dockle-raw-output', this)">
            <i class="fas fa-code"></i> View Raw Output
        </button>
        <div id="dockle-raw-output" style="display: none; margin-top: 1rem; background-color: var(--input); padding: 1rem; border-radius: var(--border-radius); font-family: 'JetBrains Mono', monospace; font-size: 0.875rem; white-space: pre-wrap; overflow-x: auto; max-height: 500px; overflow-y: auto;">
    """
    html += clean_dockle_output.replace('\n', '<br>')
    html += "</div></div>"

    html += "</div>"  # Close section-content
    return html



# Generate HTML report for container scan
def generate_container_html_report(container_data):
    """
    Generates a styled HTML report for Docker container vulnerability scan results.
    Matches the style of the scan_vulns.html page.
    
    Args:
        container_data (dict): The container vulnerability scan data.
        
    Returns:
        str: HTML report formatted to match the scan_vulns.html style.
    """
    # Define function to strip ANSI escape sequences
    def strip_ansi(text):
        """Remove ANSI escape sequences from text"""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    # Start HTML with specific styling to match scan_vulns.html
    html = """
    <style>
        /* Matching scan_vulns.html variables */
        :root {
            --primary: #0F4C75;
            --primary-light: #3282B8;
            --primary-dark: #0e3c5c;
            --secondary: #16a085;
            --secondary-dark: #138a72;
            --accent: #1B262C;
            --danger: #e74c3c;
            --warning: #f39c12;
            --success: #27ae60;
            
            /* Neutral colors */
            --background: #f5f7fa;
            --foreground: #2D3748;
            --card: #ffffff;
            --card-foreground: #1A202C;
            --border: #E2E8F0;
            --input: #EDF2F7;
            
            /* Border radius and shadows */
            --border-radius: 8px;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-md: 0 6px 12px -2px rgba(0, 0, 0, 0.1), 0 3px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }
        
        /* Docker Scan Results Styling */
        .docker-scan-results {
            margin-bottom: 1.5rem;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        
        .docker-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            padding: 1rem 1.5rem;
            border-radius: var(--border-radius) var(--border-radius) 0 0;
            font-weight: 600;
        }
        
        .docker-header i {
            font-size: 1.25rem;
        }
        
        .docker-header h3 {
            margin: 0;
        }
        
        .docker-content {
            background-color: var(--card);
            border: 1px solid var(--border);
            border-top: none;
            border-radius: 0 0 var(--border-radius) var(--border-radius);
            padding: 1.5rem;
            box-shadow: var(--shadow);
        }
        
        .container-info-section {
            margin-bottom: 1.5rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 0.75rem;
        }
        
        .info-item {
            background-color: var(--input);
            padding: 0.75rem 1rem;
            border-radius: var(--border-radius);
            transition: all 0.2s ease;
        }
        
        .info-item:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-sm);
        }
        
        .info-title {
            font-weight: 600;
            color: var(--primary);
            margin-right: 0.5rem;
        }
        
        .vulnerability-summary {
            margin-bottom: 2rem;
        }
        
        .section-header {
            background-color: var(--input);
            padding: 1rem;
            border-radius: var(--border-radius);
            margin-bottom: 1rem;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background-color 0.2s ease;
            font-weight: 600;
        }
        
        .section-header:hover {
            background-color: var(--border);
        }
        
        .section-header.collapsed .dropdown-arrow {
            transform: rotate(-90deg);
        }
        
        .dropdown-arrow {
            transition: transform 0.2s ease;
        }
        
        .section-content {
            padding: 1rem;
            border: 1px solid var(--border);
            border-radius: 0 0 var(--border-radius) var(--border-radius);
            margin-bottom: 1.5rem;
        }
        
        .section-content.collapsed {
            display: none;
        }
        
        .severity-chart {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin-top: 1rem;
        }
        
        .severity-bar {
            flex: 1;
            min-width: 120px;
            padding: 0.75rem 1rem;
            border-radius: var(--border-radius);
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 500;
            box-shadow: var(--shadow-sm);
            transition: all 0.2s ease;
        }
        
        .severity-bar:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .severity-bar.critical { background-color: var(--danger); }
        .severity-bar.high { background-color: #fd7e14; }
        .severity-bar.medium { background-color: var(--warning); }
        .severity-bar.low { background-color: var(--success); }
        .severity-bar.unknown { background-color: #718096; }
        
        .vulnerability-card {
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: var(--border-radius);
            border-left: 4px solid;
            background-color: rgba(255, 255, 255, 0.5);
            transition: all 0.2s ease;
            box-shadow: var(--shadow-sm);
        }
        
        .vulnerability-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .vulnerability-card.Critical { border-color: var(--danger); background-color: rgba(231, 76, 60, 0.05); }
        .vulnerability-card.High { border-color: #fd7e14; background-color: rgba(253, 126, 20, 0.05); }
        .vulnerability-card.Medium { border-color: var(--warning); background-color: rgba(243, 156, 18, 0.05); }
        .vulnerability-card.Low { border-color: var(--success); background-color: rgba(39, 174, 96, 0.05); }
        .vulnerability-card.Unknown { border-color: #718096; background-color: rgba(113, 128, 150, 0.05); }
        
        .vulnerability-card h4 {
            margin-top: 0;
            margin-bottom: 0.75rem;
            display: flex;
            justify-content: space-between;
            color: var(--foreground);
        }
        
        .vulnerability-details {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        
        .vuln-detail {
            background-color: var(--input);
            padding: 0.5rem 0.75rem;
            border-radius: var(--border-radius);
            font-size: 0.875rem;
            transition: background-color 0.2s ease;
        }
        
        .vuln-detail:hover {
            background-color: var(--border);
        }
        
        .severity-tag {
            font-weight: 600;
            color: white;
            padding: 0.35rem 0.75rem;
            border-radius: var(--border-radius);
        }
        
        .severity-tag.Critical { background-color: var(--danger); }
        .severity-tag.High { background-color: #fd7e14; }
        .severity-tag.Medium { background-color: var(--warning); }
        .severity-tag.Low { background-color: var(--success); }
        .severity-tag.Unknown { background-color: #718096; }
        
        .hidden-vulns {
            margin-top: 1rem;
            margin-bottom: 1rem;
        }
        
        .target-section {
            margin-bottom: 1.5rem;
            background-color: var(--card);
            border-radius: var(--border-radius);
            padding: 1rem;
            border: 1px solid var(--border);
        }
        
        .target-section h4 {
            color: var(--primary);
            margin-top: 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1rem;
        }
        
        .read-more-btn {
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: var(--border-radius);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-top: 0.75rem;
            margin-bottom: 0.75rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .read-more-btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .read-more-btn:active {
            transform: translateY(-1px);
        }
        
        /* Docker Secrets Section */
        .docker-secrets {
            padding: 1.5rem;
            background-color: #fff3cd;
            border-left: 5px solid var(--warning);
            border-radius: var(--border-radius);
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow);
        }
        
        .docker-secrets h3 {
            color: #856404;
            margin-top: 0;
            margin-bottom: 1rem;
        }
        
        .secret-card {
            background-color: #fffbe6;
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: var(--border-radius);
            border: 1px solid #ffeeba;
            box-shadow: var(--shadow-sm);
            transition: all 0.2s ease;
        }
        
        .secret-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .secret-card.high { border-left: 3px solid var(--danger); }
        .secret-card.medium { border-left: 3px solid #fd7e14; }
        .secret-card.low { border-left: 3px solid var(--warning); }
        
        .secret-card strong {
            color: var(--foreground);
        }
        
        .secret-card div {
            margin-bottom: 0.5rem;
        }
        
        .secret-match {
            font-family: 'JetBrains Mono', monospace;
            background-color: #fce8b2;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            display: inline-block;
        }
        
        /* Snyk Report Styling */
        .snyk-report {
            background-color: var(--card);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        
        .snyk-header {
            background: linear-gradient(135deg, #6042b9, #4b45a1);
            color: white;
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 600;
        }
        
        .snyk-content {
            padding: 1.5rem;
        }
        
        .snyk-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.5rem;
            background-color: var(--input);
            padding: 1rem;
            border-radius: var(--border-radius);
        }
        
        .snyk-summary-item {
            background-color: var(--card);
            padding: 1rem;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-sm);
            flex: 1;
            min-width: 150px;
            text-align: center;
            transition: all 0.2s ease;
        }
        
        .snyk-summary-item:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .snyk-summary-title {
            font-size: 0.875rem;
            color: var(--foreground);
            opacity: 0.7;
            margin-bottom: 0.5rem;
        }
        
        .snyk-summary-value {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .snyk-summary-value.critical { color: var(--danger); }
        .snyk-summary-value.high { color: #fd7e14; }
        .snyk-summary-value.medium { color: var(--warning); }
        .snyk-summary-value.low { color: var(--success); }
        
        .snyk-vuln {
            margin-bottom: 1rem;
            border-radius: var(--border-radius);
            overflow: hidden;
            border: 1px solid var(--border);
            transition: box-shadow 0.2s ease;
        }
        
        .snyk-vuln:hover {
            box-shadow: var(--shadow);
        }
        
        .snyk-vuln-header {
            display: flex;
            padding: 0.75rem 1rem;
            background-color: var(--input);
            cursor: pointer;
            align-items: center;
            justify-content: space-between;
            transition: background-color 0.2s ease;
        }
        
        .snyk-vuln-header:hover {
            background-color: var(--border);
        }
        
        .snyk-vuln.critical .snyk-vuln-header { background-color: rgba(231, 76, 60, 0.1); }
        .snyk-vuln.high .snyk-vuln-header { background-color: rgba(253, 126, 20, 0.1); }
        .snyk-vuln.medium .snyk-vuln-header { background-color: rgba(243, 156, 18, 0.1); }
        .snyk-vuln.low .snyk-vuln-header { background-color: rgba(39, 174, 96, 0.1); }
        
        .snyk-vuln-title {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 500;
        }
        
        .snyk-severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: var(--border-radius);
            color: white;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .critical .snyk-severity-badge { background-color: var(--danger); }
        .high .snyk-severity-badge { background-color: #fd7e14; }
        .medium .snyk-severity-badge { background-color: var(--warning); }
        .low .snyk-severity-badge { background-color: var(--success); }
        
        .snyk-vuln-details {
            padding: 1rem;
            background-color: var(--card);
        }
        
        .snyk-detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 0.75rem;
            margin-bottom: 1rem;
        }
        
        .snyk-detail-item {
            background-color: var(--input);
            padding: 0.75rem;
            border-radius: var(--border-radius);
            transition: background-color 0.2s ease;
        }
        
        .snyk-detail-item:hover {
            background-color: var(--border);
        }
        
        .snyk-detail-label {
            font-size: 0.75rem;
            color: var(--foreground);
            opacity: 0.7;
            margin-bottom: 0.25rem;
        }
        
        .snyk-detail-value {
            font-weight: 500;
        }
        
        .snyk-path-list {
            background-color: var(--input);
            padding: 0.75rem;
            border-radius: var(--border-radius);
            margin-top: 0.75rem;
        }
        
        .snyk-path-item {
            font-family: 'JetBrains Mono', monospace;
            padding: 0.25rem 0;
            font-size: 0.8125rem;
            color: var(--foreground);
        }
        
        .toggle-details-btn {
            background-color: transparent;
            border: none;
            cursor: pointer;
            width: 2rem;
            height: 2rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background-color 0.2s ease;
        }
        
        .toggle-details-btn:hover {
            background-color: rgba(0, 0, 0, 0.05);
        }
        
        .snyk-description {
            background-color: var(--input);
            padding: 0.75rem;
            border-radius: var(--border-radius);
            margin-top: 0.75rem;
            white-space: pre-line;
            line-height: 1.5;
        }
        
        /* Dockle Report Styling */
        .dockle-report {
            background-color: var(--card);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        
        .dockle-header {
            background: linear-gradient(135deg, #1976d2, #1565c0);
            color: white;
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 600;
        }
        
        .dockle-content {
            padding: 1.5rem;
        }
        
        .dockle-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.5rem;
            background-color: var(--input);
            padding: 1rem;
            border-radius: var(--border-radius);
        }
        
        .dockle-summary-item {
            background-color: var(--card);
            padding: 1rem;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-sm);
            flex: 1;
            min-width: 100px;
            text-align: center;
            transition: all 0.2s ease;
        }
        
        .dockle-summary-item:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .dockle-summary-title {
            font-size: 0.875rem;
            color: var(--foreground);
            opacity: 0.7;
            margin-bottom: 0.5rem;
        }
        
        .dockle-summary-value {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .dockle-summary-value.fatal { color: var(--danger); }
        .dockle-summary-value.warn { color: var(--warning); }
        .dockle-summary-value.info { color: #3498db; }
        .dockle-summary-value.pass { color: var(--success); }
        
        .dockle-issue {
            margin-bottom: 1rem;
            border-radius: var(--border-radius);
            overflow: hidden;
            border: 1px solid var(--border);
            transition: box-shadow 0.2s ease;
        }
        
        .dockle-issue:hover {
            box-shadow: var(--shadow);
        }
        
        .dockle-issue-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        
        .dockle-issue-header:hover {
            background-color: var(--border);
        }
        
        .dockle-issue-code {
            font-weight: 600;
            padding: 0.35rem 0.65rem;
            border-radius: var(--border-radius);
            margin-right: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8125rem;
        }
        
        .dockle-issue-title {
            flex-grow: 1;
            font-weight: 500;
        }
        
        .dockle-issue-level {
            padding: 0.25rem 0.75rem;
            border-radius: var(--border-radius);
            color: white;
            font-size: 0.75rem;
            font-weight: 600;
            text-align: center;
            min-width: 70px;
        }
        
        .dockle-issue.fatal .dockle-issue-header { background-color: rgba(231, 76, 60, 0.1); }
        .dockle-issue.warn .dockle-issue-header { background-color: rgba(243, 156, 18, 0.1); }
        .dockle-issue.info .dockle-issue-header { background-color: rgba(52, 152, 219, 0.1); }
        .dockle-issue.pass .dockle-issue-header { background-color: rgba(39, 174, 96, 0.1); }
        
        .dockle-issue.fatal .dockle-issue-level { background-color: var(--danger); }
        .dockle-issue.warn .dockle-issue-level { background-color: var(--warning); }
        .dockle-issue.info .dockle-issue-level { background-color: #3498db; }
        .dockle-issue.pass .dockle-issue-level { background-color: var(--success); }
        
        .dockle-issue-details {
            padding: 1rem;
            background-color: var(--card);
        }
        
        .dockle-description {
            margin-bottom: 0.75rem;
            white-space: pre-line;
            line-height: 1.5;
        }
        
        .dockle-message {
            background-color: var(--input);
            padding: 0.75rem;
            border-radius: var(--border-radius);
            font-family: 'JetBrains Mono', monospace;
            white-space: pre-wrap;
            margin-top: 0.75rem;
            color: var(--foreground);
            font-size: 0.8125rem;
            line-height: 1.5;
        }
        
        @media (max-width: 768px) {
            .severity-chart, .info-grid, .snyk-summary, .dockle-summary, .snyk-detail-grid {
                grid-template-columns: 1fr;
            }
            
            .vulnerability-details {
                flex-direction: column;
            }
        }
    </style>
    
    <!-- JavaScript for toggling details -->
    <script>
    function toggleDetails(elementId, buttonElement) {
      const element = document.getElementById(elementId);
      if (element.style.display === 'none') {
        element.style.display = 'block';
        buttonElement.innerHTML = '<i class="fas fa-chevron-up"></i>';
      } else {
        element.style.display = 'none';
        buttonElement.innerHTML = '<i class="fas fa-chevron-down"></i>';
      }
      // Prevent event propagation
      event.stopPropagation();
    }
    
    function toggleHidden(elementId, buttonElement) {
      const element = document.getElementById(elementId);
      const count = buttonElement.getAttribute('data-count');
      if (element.style.display === 'none') {
        element.style.display = 'block';
        buttonElement.innerHTML = '<i class="fas fa-chevron-up"></i> Hide ' + count + ' Vulnerabilities';
      } else {
        element.style.display = 'none';
        buttonElement.innerHTML = '<i class="fas fa-chevron-down"></i> Show ' + count + ' More Vulnerabilities';
      }
    }
    
    function toggleSection(headerElement) {
      headerElement.classList.toggle('collapsed');
      const contentId = headerElement.getAttribute('data-content');
      const contentElement = document.getElementById(contentId);
      if (contentElement) {
        contentElement.classList.toggle('collapsed');
      }
    }
    </script>
    """
    
    # Start container for Docker scan results
    html += '<div class="card docker-scan-results">'
    
    # If there's an error, display it and return
    if "error" in container_data:
        html += """
        <div class="card-header">
            <i class="fas fa-exclamation-triangle"></i>
            <span>Docker Scan Error</span>
        </div>
        <div class="card-body">
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-times-circle"></i>
                <span>%s</span>
            </div>
        </div>
        """ % container_data['error']
        html += '</div>'
    
    # Vulnerabilities Summary Section
    if "vulnerabilities" in container_data and container_data["vulnerabilities"]:
        vulns = container_data["vulnerabilities"]
        
        # Count vulnerabilities by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for vuln in vulns:
            severity = vuln.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Display summary
        html += """
        <div class="section-header" id="vuln-summary-header" onclick="toggleSection(this)" data-content="vuln-summary-content">
            <div>
                <i class="fas fa-chart-pie"></i>
                Vulnerability Summary
            </div>
            <i class="fas fa-chevron-down dropdown-arrow"></i>
        </div>
        <div class="section-content" id="vuln-summary-content">
        """
        
        # Add alert based on severity
        if severity_counts["Critical"] > 0:
            html += """
            <div class="alert alert-warning" role="alert">
                <i class="fas fa-exclamation-triangle"></i>
                <span>Critical vulnerabilities detected! Immediate action recommended.</span>
            </div>
            """
        elif severity_counts["High"] > 0:
            html += """
            <div class="alert alert-warning" role="alert">
                <i class="fas fa-exclamation-circle"></i>
                <span>High severity vulnerabilities detected. Remediation recommended.</span>
            </div>
            """
        
        # Severity chart
        html += '<div class="severity-chart">'
        for severity, count in severity_counts.items():
            if count > 0:
                severity_class = severity.lower()
                html += f"""
                <div class="severity-bar {severity_class}">
                    <span>{severity}</span>
                    <span>{count}</span>
                </div>
                """
        html += '</div>'
        html += '</div>'  # Close vulnerability summary section
        
        # Detailed Vulnerabilities Section
        html += """
        <div class="section-header" id="vuln-details-header" onclick="toggleSection(this)" data-content="vuln-details-content">
            <div>
                <i class="fas fa-bug"></i>
                Detected Vulnerabilities
            </div>
            <i class="fas fa-chevron-down dropdown-arrow"></i>
        </div>
        <div class="section-content" id="vuln-details-content">
        """
        
        # Group vulnerabilities by target
        targets = {}
        for vuln in vulns:
            target = vuln.get("target", "Unknown")
            if target not in targets:
                targets[target] = []
            targets[target].append(vuln)
        
        # Display vulnerabilities by target
        for target, target_vulns in targets.items():
            html += f'<div class="target-section">'
            html += f'<h4><i class="fas fa-crosshairs"></i> Target: {target}</h4>'
            
            # Sort by severity (Critical first)
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
            sorted_vulns = sorted(target_vulns, key=lambda v: severity_order.get(v.get("severity", "Unknown"), 5))
            
            # Show first 5 vulnerabilities
            initial_vulns = sorted_vulns[:5]
            hidden_vulns = sorted_vulns[5:]
            
            for vuln in initial_vulns:
                severity_class = vuln.get("severity", "Unknown")
                html += f"""
                <div class="vulnerability-card {severity_class}">
                    <h4>
                        <span>{vuln.get('vulnerability_id', 'Unknown')}</span>
                        <span class="severity-tag {severity_class}">{severity_class}</span>
                    </h4>
                    <div class="vulnerability-details">
                        <div class="vuln-detail"><strong>Package:</strong> {vuln.get('package_name', 'Unknown')}</div>
                        <div class="vuln-detail"><strong>Installed:</strong> {vuln.get('installed_version', 'Unknown')}</div>
                        <div class="vuln-detail"><strong>Fixed Version:</strong> {vuln.get('fixed_version', 'Not available')}</div>
                    </div>
                """
                
                # Add description if available
                if "description" in vuln and vuln["description"]:
                    description_id = f"desc_{vuln.get('vulnerability_id', '').replace('-', '_')}"
                    html += f"""
                    <div style="margin-top: 0.75rem;">
                        <button class="read-more-btn" onclick="toggleDetails('{description_id}', this)" style="padding: 0.5rem 0.75rem;">
                            <i class="fas fa-chevron-down"></i> Details
                        </button>
                        <div id="{description_id}" style="display: none; margin-top: 0.75rem; padding: 0.75rem; background-color: var(--input); border-radius: var(--border-radius);">
                            {vuln["description"]}
                        </div>
                    </div>
                    """
                
                html += '</div>'  # Close vulnerability card
            
            # Add hidden vulnerabilities section if there are more than 5
            if hidden_vulns:
                target_id = target.replace(".", "_").replace(":", "_").replace("/", "_").replace(" ", "_")
                html += f'<div class="hidden-vulns" id="hidden_{target_id}" style="display: none;">'
                
                for vuln in hidden_vulns:
                    severity_class = vuln.get("severity", "Unknown")
                    html += f"""
                    <div class="vulnerability-card {severity_class}">
                        <h4>
                            <span>{vuln.get('vulnerability_id', 'Unknown')}</span>
                            <span class="severity-tag {severity_class}">{severity_class}</span>
                        </h4>
                        <div class="vulnerability-details">
                            <div class="vuln-detail"><strong>Package:</strong> {vuln.get('package_name', 'Unknown')}</div>
                            <div class="vuln-detail"><strong>Installed:</strong> {vuln.get('installed_version', 'Unknown')}</div>
                            <div class="vuln-detail"><strong>Fixed Version:</strong> {vuln.get('fixed_version', 'Not available')}</div>
                        </div>
                    """
                    
                    # Add description if available
                    if "description" in vuln and vuln["description"]:
                        description_id = f"desc_hidden_{vuln.get('vulnerability_id', '').replace('-', '_')}"
                        html += f"""
                        <div style="margin-top: 0.75rem;">
                            <button class="read-more-btn" onclick="toggleDetails('{description_id}', this)" style="padding: 0.5rem 0.75rem;">
                                <i class="fas fa-chevron-down"></i> Details
                            </button>
                            <div id="{description_id}" style="display: none; margin-top: 0.75rem; padding: 0.75rem; background-color: var(--input); border-radius: var(--border-radius);">
                                {vuln["description"]}
                            </div>
                        </div>
                        """
                    
                    html += '</div>'  # Close vulnerability card
                
                html += '</div>'  # Close hidden vulnerabilities
                
                # Add button to toggle hidden vulnerabilities
                html += f"""
                <button class="read-more-btn" onclick="toggleHidden('hidden_{target_id}', this)" data-count="{len(hidden_vulns)}">
                    <i class="fas fa-chevron-down"></i> Show {len(hidden_vulns)} More Vulnerabilities
                </button>
                """
            
            html += '</div>'  # Close target section
        
        html += '</div>'  # Close vulnerabilities details section
    
    # Secrets Section
    if "secrets" in container_data and container_data["secrets"]:
        html += """
        <div class="section-header" id="secrets-header" onclick="toggleSection(this)" data-content="secrets-content">
            <div>
                <i class="fas fa-key"></i>
                Detected Secrets
            </div>
            <i class="fas fa-chevron-down dropdown-arrow"></i>
        </div>
        <div class="section-content" id="secrets-content">
        """
        
        # Alert for secrets
        html += """
        <div class="alert alert-warning" role="alert">
            <i class="fas fa-exclamation-triangle"></i>
            <span>Secrets detected in container! These should be removed or stored securely.</span>
        </div>
        """
        
        # List all secrets
        for secret in container_data["secrets"]:
            severity_class = secret.get("severity", "low").lower()
            html += f"""
            <div class="secret-card {severity_class}">
                <div><strong>File:</strong> {secret.get("target")}</div>
                <div><strong>Type:</strong> {secret.get("title")}</div>
                <div><strong>Severity:</strong> {secret.get("severity", "Low").capitalize()}</div>
                <div><strong>Match:</strong> <span class="secret-match">{secret.get("match", "")}</span></div>
                <div><strong>Lines:</strong> {secret.get("start_line", "?")} - {secret.get("end_line", "?")}</div>
            </div>
            """
        
        html += '</div>'  # Close secrets section
    
    # Add Snyk Report Section
    snyk_data = container_data.get("snyk")
    if snyk_data:
        html += """
        <div class="section-header" id="snyk-header" onclick="toggleSection(this)" data-content="snyk-content">
            <div>
                <i class="fas fa-shield-alt"></i>
                Snyk Security Analysis
            </div>
            <i class="fas fa-chevron-down dropdown-arrow"></i>
        </div>
        <div class="section-content" id="snyk-content">
        """
        
        # Summary section
        summary = snyk_data.get('summary', {})
        total_vulns = sum(summary.values())
        affected_packages = len(snyk_data.get('affected_packages', []))
        fixable_count = snyk_data.get('fixable_count', 0)
        
        html += '<div class="snyk-summary">'
        html += f"""
        <div class="snyk-summary-item">
            <div class="snyk-summary-title">Total Vulnerabilities</div>
            <div class="snyk-summary-value">{total_vulns}</div>
        </div>
        """
        
        # Add severity breakdown
        for severity, count in summary.items():
            if count > 0:
                html += f"""
                <div class="snyk-summary-item">
                    <div class="snyk-summary-title">{severity.capitalize()}</div>
                    <div class="snyk-summary-value {severity}">{count}</div>
                </div>
                """
        
        html += f"""
        <div class="snyk-summary-item">
            <div class="snyk-summary-title">Affected Packages</div>
            <div class="snyk-summary-value">{affected_packages}</div>
        </div>
        <div class="snyk-summary-item">
            <div class="snyk-summary-title">Fixable</div>
            <div class="snyk-summary-value">{fixable_count}</div>
        </div>
        """
        html += '</div>'  # Close summary
        
        # Vulnerabilities by severity
        vulnerabilities = snyk_data.get('vulnerabilities', [])
        severity_order = ["critical", "high", "medium", "low", "unknown"]
        
        # Group by severity
        severity_groups = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        # Display by severity
        for severity in severity_order:
            if severity in severity_groups and severity_groups[severity]:
                vulns = severity_groups[severity]
                
                html += f'<h4 style="margin-top: 1.5rem; color: var(--primary);">{severity.capitalize()} Severity Vulnerabilities ({len(vulns)})</h4>'
                
                # Show first 5 vulnerabilities
                initial_vulns = vulns[:5]
                hidden_vulns = vulns[5:]
                
                for i, vuln in enumerate(initial_vulns):
                    vuln_id = f"snyk_{severity}_{i}"
                    html += f"""
                    <div class="snyk-vuln {severity}">
                        <div class="snyk-vuln-header" onclick="toggleDetails('{vuln_id}_details', document.getElementById('{vuln_id}_toggle'))">
                            <div class="snyk-vuln-title">
                                <div class="snyk-severity-badge">{severity.upper()}</div>
                                <div>{vuln.get('id')}</div>
                                <div>in {vuln.get('package_name')} {vuln.get('installed_version')}</div>
                            </div>
                            <button id="{vuln_id}_toggle" class="toggle-details-btn" onclick="toggleDetails('{vuln_id}_details', this)">
                                <i class="fas fa-chevron-down"></i>
                            </button>
                        </div>
                        
                        <div id="{vuln_id}_details" class="snyk-vuln-details" style="display: none;">
                            <div class="snyk-detail-grid">
                                <div class="snyk-detail-item">
                                    <div class="snyk-detail-label">Package</div>
                                    <div class="snyk-detail-value">{vuln.get('package_name')}</div>
                                </div>
                                <div class="snyk-detail-item">
                                    <div class="snyk-detail-label">Installed Version</div>
                                    <div class="snyk-detail-value">{vuln.get('installed_version')}</div>
                                </div>
                                <div class="snyk-detail-item">
                                    <div class="snyk-detail-label">Fixed Version</div>
                                    <div class="snyk-detail-value">{vuln.get('fixed_version', 'Not available')}</div>
                                </div>
                                <div class="snyk-detail-item">
                                    <div class="snyk-detail-label">CVSS Score</div>
                                    <div class="snyk-detail-value">{vuln.get('cvss_score', 'N/A')}</div>
                                </div>
                    """
                    
                    # Add CVEs if available
                    cves = vuln.get('cves', [])
                    if cves:
                        html += f"""
                        <div class="snyk-detail-item">
                            <div class="snyk-detail-label">CVE IDs</div>
                            <div class="snyk-detail-value">{', '.join(cves)}</div>
                        </div>
                        """
                    
                    # Add exploit maturity if available
                    if vuln.get('exploit_maturity'):
                        html += f"""
                        <div class="snyk-detail-item">
                            <div class="snyk-detail-label">Exploit Maturity</div>
                            <div class="snyk-detail-value">{vuln.get('exploit_maturity')}</div>
                        </div>
                        """
                    
                    html += '</div>'  # Close detail grid
                    
                    # Description
                    if vuln.get('description'):
                        html += f"""
                        <div class="snyk-description">
                            <strong>Description:</strong><br>
                            {vuln.get('description')}
                        </div>
                        """
                    
                    # Paths
                    paths = vuln.get('paths', [])
                    if paths:
                        html += '<div class="snyk-path-list">'
                        html += '<strong>Vulnerable Paths:</strong>'
                        for path in paths[:5]:  # Limit to 5 paths
                            if isinstance(path, list):
                                path_str = ' > '.join(path)
                            else:
                                path_str = str(path)
                            html += f'<div class="snyk-path-item">{path_str}</div>'
                        
                        if len(paths) > 5:
                            html += f'<div class="snyk-path-item">...and {len(paths) - 5} more paths</div>'
                        
                        html += '</div>'  # Close path list
                    
                    # Link to more info
                    if vuln.get('url'):
                        html += f"""
                        <div style="margin-top: 1rem;">
                            <a href="{vuln.get('url')}" target="_blank" rel="noopener noreferrer" 
                               style="color: var(--primary); text-decoration: none; display: inline-flex; align-items: center; gap: 0.5rem;">
                                <i class="fas fa-external-link-alt"></i> More information
                            </a>
                        </div>
                        """
                    
                    html += '</div>'  # Close vuln details
                    html += '</div>'  # Close snyk-vuln
                
                # Add hidden vulnerabilities if there are more than 5
                if hidden_vulns:
                    hidden_id = f"snyk_hidden_{severity}"
                    html += f'<div id="{hidden_id}" style="display: none;">'
                    
                    for j, vuln in enumerate(hidden_vulns):
                        vuln_id = f"snyk_{severity}_hidden_{j}"
                        html += f"""
                        <div class="snyk-vuln {severity}">
                            <div class="snyk-vuln-header" onclick="toggleDetails('{vuln_id}_details', document.getElementById('{vuln_id}_toggle'))">
                                <div class="snyk-vuln-title">
                                    <div class="snyk-severity-badge">{severity.upper()}</div>
                                    <div>{vuln.get('id')}</div>
                                    <div>in {vuln.get('package_name')} {vuln.get('installed_version')}</div>
                                </div>
                                <button id="{vuln_id}_toggle" class="toggle-details-btn" onclick="toggleDetails('{vuln_id}_details', this)">
                                    <i class="fas fa-chevron-down"></i>
                                </button>
                            </div>
                            
                            <div id="{vuln_id}_details" class="snyk-vuln-details" style="display: none;">
                                <div class="snyk-detail-grid">
                                    <div class="snyk-detail-item">
                                        <div class="snyk-detail-label">Package</div>
                                        <div class="snyk-detail-value">{vuln.get('package_name')}</div>
                                    </div>
                                    <div class="snyk-detail-item">
                                        <div class="snyk-detail-label">Installed Version</div>
                                        <div class="snyk-detail-value">{vuln.get('installed_version')}</div>
                                    </div>
                                    <div class="snyk-detail-item">
                                        <div class="snyk-detail-label">Fixed Version</div>
                                        <div class="snyk-detail-value">{vuln.get('fixed_version', 'Not available')}</div>
                                    </div>
                                    <div class="snyk-detail-item">
                                        <div class="snyk-detail-label">CVSS Score</div>
                                        <div class="snyk-detail-value">{vuln.get('cvss_score', 'N/A')}</div>
                                    </div>
                        """
                        
                        # Add CVEs if available
                        cves = vuln.get('cves', [])
                        if cves:
                            html += f"""
                            <div class="snyk-detail-item">
                                <div class="snyk-detail-label">CVE IDs</div>
                                <div class="snyk-detail-value">{', '.join(cves)}</div>
                            </div>
                            """
                        
                        # Add exploit maturity if available
                        if vuln.get('exploit_maturity'):
                            html += f"""
                            <div class="snyk-detail-item">
                                <div class="snyk-detail-label">Exploit Maturity</div>
                                <div class="snyk-detail-value">{vuln.get('exploit_maturity')}</div>
                            </div>
                            """
                        
                        html += '</div>'  # Close detail grid
                        
                        # Description
                        if vuln.get('description'):
                            html += f"""
                            <div class="snyk-description">
                                <strong>Description:</strong><br>
                                {vuln.get('description')}
                            </div>
                            """
                        
                        # Paths
                        paths = vuln.get('paths', [])
                        if paths:
                            html += '<div class="snyk-path-list">'
                            html += '<strong>Vulnerable Paths:</strong>'
                            for path in paths[:5]:  # Limit to 5 paths
                                if isinstance(path, list):
                                    path_str = ' > '.join(path)
                                else:
                                    path_str = str(path)
                                html += f'<div class="snyk-path-item">{path_str}</div>'
                            
                            if len(paths) > 5:
                                html += f'<div class="snyk-path-item">...and {len(paths) - 5} more paths</div>'
                            
                            html += '</div>'  # Close path list
                        
                        # Link to more info
                        if vuln.get('url'):
                            html += f"""
                            <div style="margin-top: 1rem;">
                                <a href="{vuln.get('url')}" target="_blank" rel="noopener noreferrer" 
                                   style="color: var(--primary); text-decoration: none; display: inline-flex; align-items: center; gap: 0.5rem;">
                                    <i class="fas fa-external-link-alt"></i> More information
                                </a>
                            </div>
                            """
                        
                        html += '</div>'  # Close vuln details
                        html += '</div>'  # Close snyk-vuln
                    
                    html += '</div>'  # Close hidden container
                    
                    # Add button to toggle hidden vulnerabilities
                    html += f"""
                    <button class="read-more-btn" onclick="toggleHidden('{hidden_id}', this)" data-count="{len(hidden_vulns)}">
                        <i class="fas fa-chevron-down"></i> Show {len(hidden_vulns)} More {severity.capitalize()} Vulnerabilities
                    </button>
                    """
        
        html += '</div>'  # Close Snyk content
    
    # Dockle report section
        
    if "dockle" in container_data and container_data["dockle"]:
        html += enhance_dockle_reporting(container_data)

    
    return html


def generate_container_recommendations(container_data):
    """
    Generates security recommendations based on Docker container vulnerability scan results.
    Matches the style of the scan_vulns.html page.
    
    Args:
        container_data (dict): The container vulnerability scan data.
        
    Returns:
        str: HTML recommendations formatted to match the scan_vulns.html style.
    """
    if "error" in container_data:
        return """
        <div class="card">
            <div class="card-header">
                <i class="fas fa-exclamation-triangle"></i>
                <span>Recommendations Error</span>
            </div>
            <div class="card-body">
                <div class="alert alert-danger" role="alert">
                    <i class="fas fa-times-circle"></i>
                    <span>Unable to generate recommendations due to an error in the scan.</span>
                </div>
            </div>
        </div>
        """
    
    # Check if we have any vulnerability data
    has_vulns = "vulnerabilities" in container_data and container_data["vulnerabilities"]
    has_snyk = "snyk" in container_data and container_data["snyk"] and "vulnerabilities" in container_data["snyk"]
    has_dockle = "dockle" in container_data and container_data["dockle"]
    has_secrets = "secrets" in container_data and container_data["secrets"]
    
    if not has_vulns and not has_snyk and not has_dockle and not has_secrets:
        return """
        <div class="card">
            <div class="card-header">
                <i class="fas fa-shield-alt"></i>
                <span>Security Recommendations</span>
            </div>
            <div class="card-body">
                <div class="alert alert-success" role="alert">
                    <i class="fas fa-check-circle"></i>
                    <span>No vulnerabilities detected. Container appears secure.</span>
                </div>
                
                <div class="section-header" id="rec-best-practices-header" onclick="toggleSection(this)" data-content="rec-best-practices-content">
                    <div>
                        <i class="fas fa-clipboard-list"></i>
                        General Best Practices
                    </div>
                    <i class="fas fa-chevron-down dropdown-arrow"></i>
                </div>
                <div class="section-content" id="rec-best-practices-content">
                    <ul>
                        <li>Keep your container images regularly updated with security patches</li>
                        <li>Implement a scanning policy as part of your CI/CD pipeline</li>
                        <li>Use minimal base images to reduce attack surface</li>
                        <li>Run containers with least privileges and as non-root users</li>
                        <li>Apply resource limits to containers</li>
                    </ul>
                </div>
            </div>
        </div>
        """
    
    # Begin HTML
    html = """
    <div class="card">
        <div class="card-header">
            <i class="fas fa-shield-alt"></i>
            <span>Security Recommendations</span>
        </div>
        <div class="card-body">
    """
    
    # Count severities
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    
    # Count regular vulnerabilities
    if has_vulns:
        for vuln in container_data["vulnerabilities"]:
            severity = vuln.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Count Snyk vulnerabilities
    if has_snyk:
        snyk_data = container_data["snyk"]
        if "summary" in snyk_data:
            for severity, count in snyk_data["summary"].items():
                # Map Snyk severity to our format (capitalize first letter)
                sev_key = severity.capitalize()
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + count
    
    # Count secrets as medium by default
    if has_secrets:
        for secret in container_data["secrets"]:
            sev = secret.get("severity", "medium").capitalize()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Overall recommendation based on severity counts
    alert_class = "alert-danger"
    icon_class = "fas fa-exclamation-triangle"
    alert_message = ""
    
    if severity_counts["Critical"] > 0:
        alert_message = "This container has critical security issues. Consider rebuilding with updated packages."
        alert_class = "alert-danger"
    elif severity_counts["High"] > 5:
        alert_message = "This container has multiple high severity vulnerabilities that require immediate attention."
        alert_class = "alert-danger"
    elif severity_counts["High"] > 0:
        alert_message = "This container has high severity vulnerabilities that should be addressed."
        alert_class = "alert-warning"
    elif severity_counts["Medium"] > 10:
        alert_message = "This container has numerous medium severity vulnerabilities that should be reviewed."
        alert_class = "alert-warning"
    elif severity_counts["Medium"] > 0:
        alert_message = "This container has medium severity vulnerabilities that should be reviewed."
        alert_class = "alert-warning"
    else:
        alert_message = "This container has only low severity issues."
        alert_class = "alert-success"
        icon_class = "fas fa-info-circle"
    
    html += f"""
    <div class="alert {alert_class}" role="alert">
        <i class="{icon_class}"></i>
        <span>{alert_message}</span>
    </div>
    """
    
    # Package Vulnerabilities Section
    if has_vulns or has_snyk:
        html += """
        <div class="section-header" id="rec-packages-header" onclick="toggleSection(this)" data-content="rec-packages-content">
            <div>
                <i class="fas fa-box"></i>
                Package Vulnerabilities
            </div>
            <i class="fas fa-chevron-down dropdown-arrow"></i>
        </div>
        <div class="section-content" id="rec-packages-content">
        """
        
        # Get fixable vulnerabilities
        fixable_vulns = []
        
        # From main vulnerabilities
        if has_vulns:
            for vuln in container_data["vulnerabilities"]:
                if vuln.get("fixed_version", "") not in ["Not available", ""]:
                    fixable_vulns.append(vuln)
        
        # From Snyk vulnerabilities
        if has_snyk and "vulnerabilities" in container_data["snyk"]:
            for vuln in container_data["snyk"]["vulnerabilities"]:
                if vuln.get("fixed_version", "") not in ["Not available", ""]:
                    # Make sure we have the needed fields
                    if "severity" not in vuln:
                        vuln["severity"] = "Unknown"
                    fixable_vulns.append(vuln)
        
        # Recommendation for updates
        if fixable_vulns:
            html += "<h4>Package Updates</h4>"
            html += "<p>The following packages have fixes available and should be updated:</p>"
            
            # Group by package name
            packages = {}
            for vuln in fixable_vulns:
                pkg = vuln.get("package_name", "Unknown")
                if pkg not in packages:
                    packages[pkg] = []
                packages[pkg].append(vuln)
            
            # Display top packages with the most severe vulnerabilities
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
            sorted_packages = sorted(packages.items(), 
                                  key=lambda x: (min([severity_order.get(v.get("severity", "Unknown"), 5) for v in x[1]]), len(x[1])),
                                  reverse=False)  # Sort ascending to get most critical first
            
            html += '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; margin-top: 1rem;">'
            
            for pkg_name, pkg_vulns in sorted_packages[:10]:  # Show top 10
                # Fix for the unhashable type issue
                fixed_version_items = []
                for v in pkg_vulns:
                    fixed_ver = v.get("fixed_version", "")
                    if fixed_ver and fixed_ver != "Not available":
                        # If fixed_version is a list, add each item
                        if isinstance(fixed_ver, list):
                            fixed_version_items.extend([str(item) for item in fixed_ver if item])
                        else:
                            fixed_version_items.append(str(fixed_ver))
                
                # Remove duplicates while preserving order
                seen = set()
                fixed_versions = [x for x in fixed_version_items if not (x in seen or seen.add(x))]
                
                # Get the highest severity for this package
                severities = [v.get("severity", "Unknown") for v in pkg_vulns]
                highest_sev = min(severities, key=lambda x: severity_order.get(x, 5))
                severity_class = highest_sev.lower() if highest_sev else "unknown"
                
                html += f"""
                <div class="vulnerability-card {highest_sev}" style="margin-bottom: 0.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <strong>{pkg_name}</strong>
                        <span class="severity-tag {highest_sev}">{highest_sev}</span>
                    </div>
                    <div><strong>Update to:</strong> {', '.join(fixed_versions[:2])}</div>
                    <div><strong>Vulnerabilities:</strong> {len(pkg_vulns)}</div>
                </div>
                """
            
            html += '</div>'
            
            if len(packages) > 10:
                html += f'<p style="margin-top: 1rem; font-style: italic;">...and {len(packages) - 10} more packages need updates</p>'
        
        # General package recommendations
        html += """
        <h4 style="margin-top: 1.5rem;">Package Management Best Practices</h4>
        <ul>
            <li><strong>Keep dependencies updated:</strong> Regularly update all packages to their latest secure versions.</li>
            <li><strong>Pin package versions:</strong> Use specific versions in your Dockerfile to ensure reproducible builds.</li>
            <li><strong>Use multi-stage builds:</strong> Minimize the final image size by separating build and runtime dependencies.</li>
            <li><strong>Scan dependencies:</strong> Implement automated scanning in your CI/CD pipeline.</li>
            <li><strong>Monitor for new vulnerabilities:</strong> Subscribe to security bulletins for key packages.</li>
        </ul>
        """
        
        html += '</div>'  # Close package section
    
    # Docker Security Best Practices Section
    if has_dockle:
        html += """
        <div class="section-header" id="rec-docker-header" onclick="toggleSection(this)" data-content="rec-docker-content">
            <div>
                <i class="fab fa-docker"></i>
                Docker Security Best Practices
            </div>
            <i class="fas fa-chevron-down dropdown-arrow"></i>
        </div>
        <div class="section-content" id="rec-docker-content">
        """
        
        # Process the Dockle output for specific recommendations
        dockle_output = container_data["dockle"]
        dockle_issues = []
        
        if isinstance(dockle_output, str):
            # Simple parsing of the Dockle output
            current_issue = None
            for line in dockle_output.split('\n'):
                if '[FATAL]' in line:
                    current_issue = {'level': 'fatal', 'code': line.split()[1], 'title': ' '.join(line.split()[2:])}
                    dockle_issues.append(current_issue)
                elif '[WARN]' in line:
                    current_issue = {'level': 'warn', 'code': line.split()[1], 'title': ' '.join(line.split()[2:])}
                    dockle_issues.append(current_issue)
        
        fatal_issues = [issue for issue in dockle_issues if issue['level'] == 'fatal']
        warn_issues = [issue for issue in dockle_issues if issue['level'] == 'warn']
        
        if fatal_issues:
            html += "<h4>Critical Docker Issues</h4>"
            html += "<ul>"
            for issue in fatal_issues:
                html += f'<li><strong>{issue["code"]}:</strong> {issue["title"]}</li>'
            html += "</ul>"
        
        if warn_issues:
            html += "<h4>Docker Security Warnings</h4>"
            html += "<ul>"
            for issue in warn_issues[:5]:  # Limit to 5 warnings
                html += f'<li><strong>{issue["code"]}:</strong> {issue["title"]}</li>'
            if len(warn_issues) > 5:
                html += f'<li><em>...and {len(warn_issues) - 5} more warnings</em></li>'
            html += "</ul>"
        
        # Common Docker best practices
        html += """
        <h4 style="margin-top: 1.5rem;">Docker Security Recommendations</h4>
        <ul>
            <li><strong>Use minimal base images:</strong> Alpine, distroless, or UBI minimal images reduce attack surface.</li>
            <li><strong>Run as non-root user:</strong> Add a user with <code>USER</code> instruction and minimal permissions.</li>
            <li><strong>Set filesystem to read-only:</strong> Use read-only containers where possible.</li>
            <li><strong>Remove unnecessary tools:</strong> Delete package managers and build tools in the final image.</li>
            <li><strong>Use health checks:</strong> Implement container health monitoring.</li>
            <li><strong>Set resource limits:</strong> Define CPU and memory limits for containers.</li>
            <li><strong>Implement content trust:</strong> Sign and verify container images.</li>
        </ul>
        """
        
        html += '</div>'  # Close Docker section
    
    # Secrets Management Section
    if has_secrets:
        html += """
        <div class="section-header" id="rec-secrets-header" onclick="toggleSection(this)" data-content="rec-secrets-content">
            <div>
                <i class="fas fa-key"></i>
                Secrets Management
            </div>
            <i class="fas fa-chevron-down dropdown-arrow"></i>
        </div>
        <div class="section-content" id="rec-secrets-content">
        """
        
        # Count secrets by type
        secret_types = {}
        for secret in container_data["secrets"]:
            secret_type = secret.get("title", "Unknown")
            secret_types[secret_type] = secret_types.get(secret_type, 0) + 1
        
        html += "<h4>Detected Secrets</h4>"
        html += "<p>The following types of secrets were found in your container:</p>"
        
        html += '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 1rem; margin: 1rem 0;">'
        for secret_type, count in secret_types.items():
            html += f"""
            <div class="secret-card medium">
                <div><strong>Type:</strong> {secret_type}</div>
                <div><strong>Occurrences:</strong> {count}</div>
            </div>
            """
        html += '</div>'
        
        html += """
        <h4 style="margin-top: 1.5rem;">Secrets Management Recommendations</h4>
        <ul>
            <li><strong>Use secrets management:</strong> Implement a dedicated tool like HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets.</li>
            <li><strong>Remove hardcoded secrets:</strong> Never store credentials, tokens, or keys in your container images.</li>
            <li><strong>Use build arguments:</strong> Pass secrets at build time instead of embedding them.</li>
            <li><strong>Implement environment variables:</strong> For non-critical configuration, use environment variables.</li>
            <li><strong>Add pre-commit hooks:</strong> Prevent accidental commits of sensitive files.</li>
            <li><strong>Rotate credentials:</strong> Regularly update secrets and keys.</li>
            <li><strong>Implement least privilege:</strong> Give containers access only to the secrets they need.</li>
        </ul>
        """
        
        html += '</div>'  # Close secrets section
    
    # General Security Recommendations
    html += """
    <div class="section-header" id="rec-general-header" onclick="toggleSection(this)" data-content="rec-general-content">
        <div>
            <i class="fas fa-shield-alt"></i>
            General Security Recommendations
        </div>
        <i class="fas fa-chevron-down dropdown-arrow"></i>
    </div>
    <div class="section-content" id="rec-general-content">
        <h4>Container Security Best Practices</h4>
        <ul>
            <li><strong>Implement least privilege:</strong> Run containers with minimal permissions using security contexts.</li>
            <li><strong>Set resource limits:</strong> Define CPU and memory constraints for each container.</li>
            <li><strong>Configure network policies:</strong> Restrict container-to-container communication.</li>
            <li><strong>Use read-only file systems:</strong> When possible, mount file systems as read-only.</li>
            <li><strong>Regular security scans:</strong> Schedule periodic vulnerability assessments of containers.</li>
            <li><strong>Monitor containers:</strong> Implement real-time monitoring for suspicious activities.</li>
            <li><strong>Implement runtime protection:</strong> Consider tools that monitor container runtime behavior.</li>
        </ul>
        
        <h4 style="margin-top: 1.5rem;">Infrastructure Security</h4>
        <ul>
            <li><strong>Secure the host:</strong> Keep the host OS and container runtime updated.</li>
            <li><strong>Isolate containers:</strong> Run sensitive containers on dedicated hosts.</li>
            <li><strong>Segment networks:</strong> Use network segmentation to isolate container environments.</li>
            <li><strong>Automate security:</strong> Integrate security checks into CI/CD pipelines.</li>
            <li><strong>Implement logging:</strong> Collect and analyze container logs for security events.</li>
        </ul>
    </div>
    """
    
    # Close main containers
    html += '</div></div>'
    
    return html

import requests
import json
import os
from dotenv import load_dotenv  # Optional, for handling environment variables

# Load API key from environment variables (recommended approach)
load_dotenv()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
print(f"API key configured: {'Yes' if os.environ.get('ANTHROPIC_API_KEY') else 'No'}")
from dotenv import load_dotenv
load_dotenv()

# Updated API authentication and error handling for enhanced report generation

import requests
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_enhanced_scan_report(scan_results, target_ip):
    """
    Generate an enhanced, more readable vulnerability scan report
    
    Args:
        scan_results (str): Raw Nmap scan results as text
        target_ip (str): The IP address of the scanned target
        
    Returns:
        str: Enhanced and formatted scan report
    """
    # Get API key from environment with proper error handling
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY environment variable not set")
        return f"""
# ENHANCED SCAN REPORT (FALLBACK VERSION)

## Target: {target_ip}
## Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Note: The enhanced report could not be generated because the Anthropic API key is not configured.
Below are the raw scan results:

{scan_results}
"""
    
    headers = {
        "x-api-key": api_key,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01"
    }
    
    # Prepare a clear, well-structured prompt
    prompt = f"""
    I have a vulnerability scan result from an IoT device that I need formatted in a more understandable way.
    Please organize it by port, clearly describe each vulnerability with severity and impact, and provide specific 
    security recommendations. Here's the scan result for IP {target_ip}:
    
    {scan_results}
    
    Format the output as a clean markdown report with these sections:
    1. Executive Summary - A brief overview of findings
    2. Critical Vulnerabilities - Detailed explanation of critical issues found
    3. High Risk Vulnerabilities - Details on high severity issues
    4. Medium and Low Risk Issues - Brief summary of less severe issues
    5. Recommendations - Specific actionable security recommendations
    
    For each vulnerability, include the CVE number, affected service/port, and detailed explanation.
    """
    
    payload = {
        "model": "claude-3-7-sonnet-20250219",
        "max_tokens": 4000,
        "temperature": 0.1,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    
    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=payload,
            timeout=150  # 30-second timeout
        )
        
        if response.status_code == 200:
            result = response.json()
            enhanced_report = result["content"][0]["text"]
            return enhanced_report
        elif response.status_code == 401:
            logger.error(f"API authentication failed: {response.text}")
            return f"""
# ENHANCED SCAN REPORT (AUTHENTICATION ERROR)

## Target: {target_ip}
## Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Note: The enhanced report could not be generated due to an API authentication error.
Please verify that your Anthropic API key is valid and properly configured.

Below are the raw scan results:

{scan_results}
"""
        else:
            logger.error(f"API call failed with status code {response.status_code}: {response.text}")
            return f"Error: API call failed with status code {response.status_code}\n{response.text}"
            
    except requests.RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        return f"Error: Request to API failed - {str(e)}"
    except Exception as e:
        logger.error(f"Error generating enhanced report: {str(e)}", exc_info=True)
        return f"Error generating enhanced report: {str(e)}"

# Function to integrate with your scan_vulnerabilities route
def save_enhanced_report(raw_scan_output, target_ip, output_file):
    """
    Generate and save an enhanced scan report to a file
    
    Args:
        raw_scan_output (str): The raw output from nmap or other scan tools
        target_ip (str): The IP address of the scanned target
        output_file (str): Path where to save the enhanced report
    
    Returns:
        bool: Success or failure
    """
    try:
        # Prepend target information to the scan results
        full_scan_data = f"Host: {target_ip}\n\n{raw_scan_output}"
        
        # Generate enhanced report
        enhanced_report = generate_enhanced_scan_report(full_scan_data, target_ip)
        
        # Save to file with error handling
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(enhanced_report)
        
        logger.info(f"Enhanced report saved to {output_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to save enhanced report: {str(e)}", exc_info=True)
        
        # Create a fallback report in case of failure
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"""
# SCAN REPORT (FALLBACK VERSION)

## Target: {target_ip}
## Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Note: The enhanced report generator encountered an error: {str(e)}

Below are the raw scan results:

{raw_scan_output}
""")
            logger.info(f"Fallback report saved to {output_file}")
            return True
        except Exception as fallback_error:
            logger.error(f"Failed to save fallback report: {str(fallback_error)}", exc_info=True)
            return False
    

def run_background_scan(ip, task_id):
    filename = f"scans/{task_id}.txt"
    enhanced_filename = f"scans/{task_id}_enhanced.txt"
    try:
        with task_lock:
            background_tasks[task_id] = {'status': 'scanning', 'progress': 0, 'start_time': datetime.now().isoformat()}
        
        # Update progress to 10% - Starting scan
        with task_lock:
            background_tasks[task_id]['progress'] = 10
        
        nm = nmap.PortScanner()
        scan_args = '-p 1-1024,1025-49151 -sV --script vuln --script-timeout 2m'
        
        # Start a progress update thread
        def update_progress():
            progress = 10
            while progress < 95:
                time.sleep(10)  # Update every 10 seconds
                progress += 5
                with task_lock:
                    task = background_tasks.get(task_id)
                    if not task or task.get('status') != 'scanning':
                        break
                    background_tasks[task_id]['progress'] = progress
        
        progress_thread = threading.Thread(target=update_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        # Run the actual scan
        nm.scan(hosts=ip, arguments=scan_args, timeout=1200)
        
        # Update progress to 95% - Processing results
        with task_lock:
            background_tasks[task_id]['progress'] = 95
        
        scan_results = []
        
        for host in nm.all_hosts():
            scan_results.append(f"Host: {host}")
            
            # OS Detection
            if 'osmatch' in nm[host]:
                scan_results.append("OS Matches:")
                for osmatch in nm[host]['osmatch']:
                    scan_results.append(f"- {osmatch['name']} ({osmatch['accuracy']}%)")

            # Port/Service Info
            for proto in nm[host].all_protocols():
                scan_results.append(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    port_entry = [
                        f"Port {port}: {service['state']}",
                        f"  Service: {service.get('name', 'unknown')}",
                        f"  Version: {service.get('product', '')} {service.get('version', '')}",
                        f"  Extra: {service.get('extrainfo', '')}"
                    ]
                    
                    # Add vulnerability scripts for this port
                    if 'script' in service:
                        port_entry.append("  Vulnerabilities:")
                        for script_name, script_output in service['script'].items():
                            port_entry.append(f"    - {script_name}: {script_output}")
                    
                    scan_results.append("\n".join(port_entry))

            # Host-level vulnerabilities
            if 'hostscript' in nm[host]:
                scan_results.append("\nHost-level Vulnerabilities:")
                for script in nm[host]['hostscript']:
                    scan_results.append(f"- {script['id']}: {script['output']}")

        # Save raw results
        raw_scan_text = "\n".join(scan_results)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(raw_scan_text)
        
        # Generate enhanced report using Claude API
        save_enhanced_report(raw_scan_text, ip, enhanced_filename)
        
        # Update to completed with 100% progress
        with task_lock:
            background_tasks[task_id] = {
                'status': 'completed', 
                'file': filename,
                'enhanced_file': enhanced_filename,
                'progress': 100,
                'completed_at': datetime.now().isoformat()
            }
    
    except Exception as e:
        with task_lock:
            background_tasks[task_id] = {
                'status': 'failed', 
                'error': str(e),
                'failed_at': datetime.now().isoformat()
            }
        if os.path.exists(filename):
            os.remove(filename)
        app.logger.error(f"Scan failed for {ip}: {str(e)}")
    finally:
        if background_tasks.get(task_id, {}).get('status') != 'completed':
            if os.path.exists(filename):
                os.remove(filename)




@app.route('/check_scan_status')
def check_scan_status():
    task_id = session.get('scan_task_id')
    if not task_id:
        return jsonify({'status': 'no_active_scan'})
    
    with task_lock:
        task = background_tasks.get(task_id, {})
    
    # Auto-cleanup for stalled scans
    if task.get('status') == 'scanning':
        start_time = datetime.fromisoformat(task.get('start_time', datetime.now().isoformat()))
        if datetime.now() - start_time > timedelta(minutes=30):
            with task_lock:
                background_tasks[task_id]['status'] = 'failed'
                background_tasks[task_id]['error'] = 'Scan timed out after 30 minutes'
            task = background_tasks[task_id]
    
    # Include html_report and recommendations in the response
    response = {
        'status': task.get('status', 'no_active_scan'),
        'progress': task.get('progress', 0),
        'error': task.get('error', None),
        'html_report': task.get('html_report', None),
        'recommendations': task.get('recommendations', None)
    }
    return jsonify(response)


# Replace the download_full_scan route in app.py

# Fixed implementation for the download_full_scan route in app.py

@app.route('/download_full_scan/<report_type>')
@login_required
def download_full_scan(report_type):
    """
    Download the full scan results file.
    
    Args:
        report_type: Either 'raw' or 'enhanced' to specify which report to download
    
    Returns:
        The scan results file as a downloadable attachment
    """
    # Get task ID from session
    task_id = session.get('scan_task_id')
    if not task_id:
        flash('No scan results available', 'error')
        return redirect(url_for('scan_vulns'))
    
    # Look up task information with proper locking
    with task_lock:
        task = background_tasks.get(task_id, {})
        if report_type == 'enhanced':
            filename = task.get('enhanced_file')
            download_name = 'enhanced_scan_results.txt'
        else:  # Default to raw
            filename = task.get('file')
            download_name = 'raw_scan_results.txt'
    
    # Validate that we have a file to download
    if not filename or not os.path.exists(filename):
        logger.error(f"Download failed: File {filename} not found for task {task_id}")
        flash('Scan results not ready or file not found', 'error')
        return redirect(url_for('scan_vulns'))
    
    try:
        # Log the download attempt for debugging
        logger.info(f"Serving download: {filename} as {download_name} for task {task_id}")
        
        # Read file content to ensure it's valid before sending
        with open(filename, 'r', encoding='utf-8') as f:
            file_content = f.read()
            if not file_content:
                raise ValueError("Empty file content")
        
        # Send the file with proper headers
        response = send_file(
            filename,
            mimetype='text/plain',
            as_attachment=True,
            download_name=download_name
        )
        
        # Add Cache-Control header to prevent caching
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f"Download failed: {str(e)}", exc_info=True)
        flash(f'Download error: {str(e)}', 'error')
        return redirect(url_for('scan_vulns'))


@app.route('/clear_scan_results', methods=['POST'])
@login_required
def clear_scan_results():
    task_id = session.pop('scan_task_id', None)
    
    if task_id:
        with task_lock:
            task = background_tasks.pop(task_id, None)
            
            if task and 'file' in task and os.path.exists(task['file']):
                try:
                    os.remove(task['file'])
                except Exception as e:
                    logger.error(f"Failed to remove scan file: {str(e)}", exc_info=True)
    
    return jsonify({"message": "Scan stopped and results cleared."})


# Enhanced detection patterns
CRED_PATTERNS = re.compile(
    r'(password|secret|admin|token|credential|key|auth|api_key)(\s*[=:]\s*[\'"]?[^\s\'"};]+)',
    re.IGNORECASE
)

WEAK_ALGORITHMS = {
    'md5', 'sha1', 'des', 'rc4', '3des', 'blowfish',
    'ssl_version=1.0', 'ssl_version=2.0', 'ssl_version=3.0',
    'tls_version=1.0', 'tls_version=1.1'
}

INSECURE_SERVICES = {
    'telnetd', 'ftpd', 'rshd', 
    'rexecd', 'rlogind', 'tftpd'
}

DEBUG_PATTERNS = {
    'DW_TAG', 'debug_mode', 'DEBUG=', 
    'TRACE=', 'development_mode',
    'debug_level'
}

SSL_PATTERNS = [
    'libssl*', 'libcrypto*', '*openssl*', '*tls*',
    'ssl.conf', 'openssl.cnf', '*.pem', '*.key'
]

INSECURE_PROTOCOLS = {
    'telnet', 'ftp', 'http', 'plaintext',
    'telnet_enabled=true', 'ftp_enabled=true',
    'ssh_password_auth=true', 'debug_mode=true'
}


# Configure caching for CVE checks
CVE_CACHE = cachetools.TTLCache(maxsize=1000, ttl=3600)  # 1 hour cache

# Constants
ALLOWED_EXTENSIONS = {'bin', 'img', 'hex', 'rom', 'zip'}
ALLOWED_MIME_TYPES = {
    'application/octet-stream',
    'application/zip',
    'application/x-zip-compressed'
}


def find_insecure_services(directory: str) -> List[Tuple[str, str]]:
    """Find insecure services in startup scripts"""
    services = []
    
    for root, _, files in os.walk(directory):
        if 'init.d' in root:
            for filename in files:
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        for service in INSECURE_SERVICES:
                            if service in content:
                                services.append((
                                    os.path.relpath(file_path, directory),
                                    f"Insecure service detected: {service}"
                                ))
                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {str(e)}")
                    continue
    return services

CVE_CACHE = {}  # Cache to store CVE results for libraries

def check_cve_versions(libraries: List[Dict]) -> List[Dict]:
    """Check for CVEs using version-specific queries with secure API handling."""

    LIBRARY_NAME_MAPPING = {
    # SSL/TLS
    'libssl': 'openssl',
    'libssl3': 'openssl',
    'libssl1.0.0': 'openssl',
    'libcrypto': 'openssl',
    
    # Common IoT Libraries
    'libcurl': 'curl',
    'libmodbus': 'libmodbus',
    'libcoap': 'libcoap',
    'libmosquitto': 'mosquitto',
    
    # Industrial Protocols
    'libopcua': 'open62541',
    'libprofinet': 'p-net',
    
    # File Parsing
    'libupnp': 'pupnp',
    'libcjson': 'cjson',
    
    # Add version-agnostic patterns
    re.compile(r'^libssl[0-9.]*$'): 'openssl',
    re.compile(r'^libcurl[0-9.]*$'): 'curl'
}
    

    CVE_CACHE.clear()
    cve_results = []
    
    if not libraries or not isinstance(libraries, list):
        logger.warning("Invalid libraries format provided to check_cve_versions")
        return cve_results

    # Security headers configuration
    SECURE_HEADERS = {
        'User-Agent': 'IoT-Security-Scanner/2.0 (https://yourapp.com)',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive'
    }

    for lib in libraries:
        try:
            # Extract library metadata
            lib_path = lib.get('path', 'Unknown')
            version = lib.get('version', 'unknown').split('-')[0]  # Handle version strings like 1.0.0f
            description = lib.get('description', '')
            
            # Normalize library name using enhanced mapping
            lib_name = os.path.basename(lib_path).split('.')[0].lower()
            lib_name = LIBRARY_NAME_MAPPING.get(lib_name, lib_name)
            
            # Create version-aware cache key
            cache_key = f"{lib_name}_{version.replace('.', '_')}"
            
            if cache_key in CVE_CACHE:
                cve_results.extend(CVE_CACHE[cache_key])
                continue

            lib_cves = []
            nvd_key = os.environ.get('NVD_API_KEY')

            # 1. Query NVD API with CPE format
            if nvd_key:
                try:
                    nvd_url = (
                        f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
                        f"cpeMatchString=cpe:2.3:a:*:{lib_name}:{version}:*:*:*:*:*:*:*"
                    )
                    response = requests.get(
                        nvd_url,
                        headers={**SECURE_HEADERS, 'apiKey': nvd_key},
                        timeout=15,
                        allow_redirects=False
                    )
                    
                    if response.status_code == 200:
                        for vuln in response.json().get('vulnerabilities', []):
                            cve_data = vuln['cve']
                            metrics = cve_data.get('metrics', {})
                            cvss = 0.0
                            
                            # Get highest available CVSS score
                            if metrics.get('cvssMetricV31'):
                                cvss = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                            elif metrics.get('cvssMetricV30'):
                                cvss = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                            elif metrics.get('cvssMetricV2'):
                                cvss = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                                
                            lib_cves.append({
                                'id': cve_data['id'],
                                'summary': next((desc['value'] for desc in cve_data['descriptions'] 
                                              if desc['lang'] == 'en'), ''),
                                'cvss': cvss,
                                'source': 'NVD',
                                'published': cve_data.get('published', ''),
                                'last_modified': cve_data.get('lastModified', '')
                            })
                    elif response.status_code == 403:
                        logger.error("NVD API rate limit exceeded with valid key")
                    
                except Exception as nvd_error:
                    logger.error(f"NVD query failed: {str(nvd_error)}")

            # 2. Fallback to CIRCL API
            try:
                circl_url = f"https://cve.circl.lu/api/cve/{lib_name}/{version}"
                response = requests.get(
                    circl_url,
                    headers=SECURE_HEADERS,
                    timeout=10,
                    verify=True  # Enforce SSL verification
                )
                
                if response.status_code == 200:
                    cve = response.json()
                    if cve.get('id'):
                        lib_cves.append({
                            'id': cve['id'],
                            'summary': cve.get('summary', ''),
                            'cvss': cve.get('cvss', 0.0),
                            'source': 'CIRCL',
                            'published': cve.get('Published', ''),
                            'last_modified': cve.get('Modified', '')
                        })
                        
            except Exception as circl_error:
                logger.debug(f"CIRCL query failed: {str(circl_error)}")

            # 3. Query OSV.dev
            try:
                osv_payload = {
                    "package": {
                        "name": lib_name,
                        "ecosystem": "OSS-Fuzz",
                        "version": version
                    },
                    "version": version
                }
                
                response = requests.post(
                    "https://api.osv.dev/v1/query",
                    json=osv_payload,
                    headers={**SECURE_HEADERS, 'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    for vuln in response.json().get('vulns', []):
                        lib_cves.append({
                            'id': vuln['id'],
                            'summary': vuln.get('details', ''),
                            'cvss': vuln.get('severity', [{}])[0].get('score', 0.0),
                            'source': 'OSV',
                            'published': vuln.get('published', ''),
                            'last_modified': vuln.get('modified', '')
                        })
                        
            except Exception as osv_error:
                logger.debug(f"OSV query failed: {str(osv_error)}")

            # Enrich and deduplicate results
            seen_ids = set()
            final_cves = []
            
            for cve in lib_cves:
                if cve['id'] not in seen_ids:
                    seen_ids.add(cve['id'])
                    final_cves.append({
                        **cve,
                        'library': lib_name,
                        'version': version,
                        'file_path': lib_path,
                        'description': description,
                        'severity': _calculate_severity(cve['cvss'])
                    })
            
            # Cache and extend results
            CVE_CACHE[cache_key] = final_cves
            cve_results.extend(final_cves)
            
            # Rate limiting
            time.sleep(0.2 if nvd_key else 1.5)

        except Exception as e:
            logger.error(f"Failed to process {lib_path}: {str(e)}")
            continue

    return cve_results

def _calculate_severity(cvss: float) -> str:
    """CVSS v3.1 severity ratings"""
    if cvss >= 9.0: return 'CRITICAL'
    if cvss >= 7.0: return 'HIGH'
    if cvss >= 4.0: return 'MEDIUM'
    if cvss > 0.0: return 'LOW'
    return 'INFO'

def find_weak_encryption(directory: str) -> List[Dict]:
    """Find weak encryption algorithms"""
    weak_crypto = []
    
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read().lower()
                    for algo in WEAK_ALGORITHMS:
                        if algo in content:
                            weak_crypto.append({
                                'file': os.path.relpath(file_path, directory),
                                'algorithm': algo.upper(),
                                'context': extract_context(content, algo)
                            })
            except Exception as e:
                logger.debug(f"Error reading {file_path}: {str(e)}")
                continue
    
    return weak_crypto

def find_debug_symbols(directory: str) -> List[Dict]:
    """
    Find debug symbols in binary files with WSL fallback
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        List of dictionaries with debug symbol findings
    """
    debug_files = []
    
    for file_path in Path(directory).rglob('*'):
        if not file_path.is_file():
            continue

        try:
            # Check if WSL is available
            wsl_available = False
            try:
                subprocess.run(['wsl', 'echo', 'test'], 
                              capture_output=True, 
                              timeout=5, 
                              check=True)
                wsl_available = True
            except (subprocess.SubprocessError, FileNotFoundError):
                wsl_available = False
            
            if wsl_available:
                # Run readelf through WSL with debug dump
                result = subprocess.run(
                    ['wsl', 'readelf', '--debug-dump', str(file_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False  # Don't raise exception on non-zero exit
                )
            else:
                # Try native readelf if available
                result = subprocess.run(
                    ['readelf', '--debug-dump', str(file_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False  # Don't raise exception on non-zero exit
                )
            
            # Only process if command was successful
            if result.returncode == 0:
                # Parse debug symbols from output
                symbols = []
                for line in result.stdout.split('\n'):
                    if 'DW_TAG' in line:  # Look for DWARF debug tags
                        symbol = line.split('DW_TAG_')[-1].split(' ')[0]
                        symbols.append(symbol)
                
                if symbols:
                    debug_files.append({
                        'file': str(file_path.relative_to(directory)),
                        'symbols': symbols[:10]  # Show first 10 symbols
                    })

        except subprocess.CalledProcessError:
            continue  # Skip files that aren't ELF binaries
        except Exception as e:
            logger.warning(f"Debug analysis failed for {file_path}: {str(e)}")
            continue

    return debug_files[:20]  # Return maximum 20 files with debug symbols

def detect_architecture_via_binaries(directory: str) -> Dict:
    """
    Detect architecture by analyzing binary files using objdump and readelf.
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        Dictionary with architecture information
    """
    for bin_path in Path(directory).rglob('*'):
        if bin_path.is_file() and bin_path.suffix in {'.so', '.ko', '.bin', '.elf'}:
            try:
                # Check using objdump
                result = subprocess.run(
                    ['objdump', '-f', str(bin_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False  # Don't raise exception on non-zero exit
                )
                if result.returncode == 0:
                    if 'architecture: arm' in result.stdout.lower():
                        return {'architecture': 'ARM'}
                    elif 'architecture: i386' in result.stdout.lower() or 'x86' in result.stdout.lower():
                        return {'architecture': 'x86_64'}

                # Fallback to readelf
                result = subprocess.run(
                    ['readelf', '-h', str(bin_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False  # Don't raise exception on non-zero exit
                )
                if result.returncode == 0:
                    if 'ARM' in result.stdout:
                        return {'architecture': 'ARM'}
                    elif 'x86' in result.stdout:
                        return {'architecture': 'x86_64'}
            except Exception as e:
                logger.debug(f"Architecture detection error: {str(e)}")
                continue
    return {'architecture': 'Unknown'}

def detect_architecture_via_script_headers(directory: str) -> Dict:
    """
    Detect architecture based on script headers and configuration files.
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        Dictionary with architecture information
    """
    arch_keywords = {
        'x86_64': ['x86_64', 'amd64', 'intel64'],
        'ARM': ['armv7', 'armv8', 'aarch64', 'arm']
    }
    for file_path in Path(directory).rglob('*'):
        if file_path.is_file() and file_path.suffix in {'.sh', '.conf', '.config', '.txt'}:
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read(1024).lower()  # Read first 1KB for efficiency
                    for arch, keywords in arch_keywords.items():
                        if any(keyword in content for keyword in keywords):
                            return {'architecture': arch}
            except Exception as e:
                logger.debug(f"Error reading {file_path}: {str(e)}")
                continue
    return {'architecture': 'Unknown'}

def extract_firmware_metadata(directory: str) -> Dict:
    """
    Enhanced metadata extraction with multiple fallback methods
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        Dictionary with firmware metadata
    """
    metadata = {
        'vendor': 'Unknown',
        'version': 'Unknown',
        'architecture': 'Unknown',
        'build_date': 'Unknown',
        'platform': 'Unknown'
    }

    # Check dedicated metadata files first
    meta_files = {
        'version.txt': ('version', 0.9),
        'vendor.info': ('vendor', 0.9),
        'build_info': ('build_date', 0.7),
        'platform': ('platform', 0.8)
    }

    for file_name, (key, confidence) in meta_files.items():
        for path in Path(directory).rglob(file_name):
            try:
                with open(path, 'r', errors='ignore') as f:
                    metadata[key] = f.read().strip()
                    metadata[f'{key}_confidence'] = confidence
            except Exception as e:
                logger.debug(f"Error reading metadata file {path}: {str(e)}")
                continue

    # Architecture detection using multiple methods
    arch_detectors = [
        detect_architecture_via_file,
        detect_architecture_via_binaries,
        detect_architecture_via_script_headers
    ]
    
    for detector in arch_detectors:
        if metadata['architecture'] == 'Unknown':
            try:
                result = detector(directory)
                if result['architecture'] != 'Unknown':
                    metadata['architecture'] = result['architecture']
                    break
            except Exception as e:
                logger.warning(f"Architecture detector failed: {str(e)}")
                continue

    return metadata


# In app.py, add:
def analyze_shadow_file(directory: str) -> List[Dict]:
    """Analyze /etc/shadow entries for weak hashes"""
    shadow_path = os.path.join(directory, 'etc/shadow')
    findings = []
    
    if os.path.exists(shadow_path):
        with open(shadow_path, 'r') as f:
            for line in f:
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        algo = {
                            '$1$': 'MD5',
                            '$2a$': 'Blowfish',
                            '$5$': 'SHA-256',
                            '$6$': 'SHA-512'
                        }.get(parts[1][0:3], 'UNKNOWN')
                        findings.append({
                            'user': parts[0],
                            'hash': parts[1],
                            'algorithm': algo,
                            'risk': 'high' if algo in ['MD5', 'Blowfish'] else 'medium'
                        })
    return findings


def find_hardcoded_creds(directory: str) -> List[Tuple]:
    """Find hardcoded credentials in files"""
    matches = []
    
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                # Try text files first
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    for match in CRED_PATTERNS.finditer(content):
                        matches.append((
                            os.path.relpath(file_path, directory),
                            highlight_context(content, match.start(), match.end())
                        ))
                
                # Also check binary files using strings command
                if filename.endswith(('.bin', '.so', '.elf', '.ko')):
                    try:
                        result = subprocess.run(
                            ['strings', file_path],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        if result.returncode == 0:
                            for match in CRED_PATTERNS.finditer(result.stdout):
                                matches.append((
                                    os.path.relpath(file_path, directory),
                                    f"Binary file contains: {match.group(0)}"
                                ))
                    except Exception as e:
                        logger.debug(f"Error running strings on {file_path}: {str(e)}")
                        
            except Exception as e:
                logger.debug(f"Error reading {file_path}: {str(e)}")
                continue
                
    return matches


def analyze_file_structure(directory: str) -> List[str]:
    """
    Improved file structure analysis with risk scoring
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        List of strings with file structure information
    """
    structure = []
    risk_patterns = {
        '*.pem': 3, 
        '*.key': 3,
        'shadow': 3,
        'passwd': 2,
        '*.cfg': 2,
        '*.db': 2
    }

    for path in Path(directory).rglob('*'):
        if path.is_dir():
            risk_score = 0
            try:
                dir_name = path.relative_to(directory)
                for child in path.iterdir():
                    for pattern, score in risk_patterns.items():
                        if child.match(pattern):
                            risk_score += score
                
                indent = '│  ' * len(path.relative_to(directory).parts)
                structure.append(
                    f"{indent}├─ {dir_name.name}/ [Risk: {risk_score}]"
                )
            except Exception as e:
                logger.debug(f"Error analyzing directory {path}: {str(e)}")
                continue
        else:
            try:
                indent = '│  ' * len(path.relative_to(directory).parts[:-1])
                for pattern, score in risk_patterns.items():
                    if path.match(pattern):
                        structure.append(
                            f"{indent}│  ⚠ {path.name} (Risk: {score})"
                        )
                        break
            except Exception as e:
                logger.debug(f"Error analyzing file {path}: {str(e)}")
                continue

    return [line.split(' [Risk')[0] for line in structure[:200]]

def check_wsl_availability():
    """Check if WSL and required tools are available."""
    try:
        result = subprocess.run(
            ['wsl', 'which', 'strings'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            logger.warning("WSL or 'strings' command not available. SSL version detection may be limited.")
    except FileNotFoundError:
        logger.warning("WSL not installed. SSL version detection will use filename fallback.")


def get_ssl_version(lib_path: str) -> str:
    """Extract SSL version using WSL strings or filename fallback."""
    version = "Unknown"
    try:
        # Check if running on Windows
        if os.name == 'nt':
            # Convert Windows path to WSL path
            wsl_path = lib_path.replace('\\', '/').replace('C:', '/mnt/c')
            
            # Try WSL strings command
            result = subprocess.run(
                ['wsl', 'strings', wsl_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
        else:
            # Use native strings on Linux/macOS
            result = subprocess.run(
                ['strings', lib_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
        
        # Extract version from strings output
        version_match = re.search(
            r'(OpenSSL|openssl)[-_]?(\d+\.\d+\.\d+\w*)', 
            result.stdout, 
            re.IGNORECASE
        )
        if version_match:
            return version_match.group(2).strip()
        
        # Fallback: Extract version from filename
        filename = os.path.basename(lib_path)
        filename_match = re.search(r'(\d+\.\d+\.\d+\w*)', filename)  # Include letters like 'g'
        if filename_match:
            return filename_match.group(1)
        
    except Exception as e:
        logger.error(f"SSL version detection failed: {str(e)}")
    
    return version
    
    
def find_lib_issues(directory: str) -> List[Dict]:
    """Combined detection of SSL-related and outdated libraries"""
    lib_issues = []
    ssl_patterns = ['libssl*', 'libcrypto*', '*openssl*', '*tls*']    
    version_pattern = re.compile(r'(\d+\.\d+\.\d+)')  # Version pattern
    
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, directory)
            
            # Prioritize SSL library detection
            if any(fnmatch.fnmatch(filename, pattern) for pattern in ssl_patterns):
                version = get_ssl_version(file_path)
                lib_issues.append({
                    'type': 'ssl',
                    'path': rel_path,
                    'version': version,
                    'description': f"SSL Library ({version})" if version != 'Unknown' else "SSL Library"
                })

            
            # Detect outdated libraries (non-SSL)
            elif filename.endswith(('.so', '.dll', '.lib', '.a')):
                # Check filename for version
                match = version_pattern.search(filename)
                if match:
                    version = match.group(1)
                    lib_issues.append({
                        'type': 'outdated',
                        'path': rel_path,
                        'version': version,
                        'description': f"Outdated version {version} detected in filename"
                    })
                else:
                    # Check file content for version strings
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read(4096).decode('ascii', errors='ignore')
                            match = version_pattern.search(content)
                            if match:
                                version = match.group(1)
                                lib_issues.append({
                                    'type': 'outdated',
                                    'path': rel_path,
                                    'version': version,
                                    'description': f"Outdated version {version} detected in content"
                                })
                    except Exception as e:
                        logger.debug(f"Error checking {file_path}: {str(e)}")
                        continue

    return lib_issues       
    

def find_insecure_protocols(directory: str) -> List[Tuple]:
    """Find insecure protocols in configuration files"""
    insecure_services = []
    
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(('.conf', '.cfg', '.ini', '.sh')):
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        for protocol in INSECURE_PROTOCOLS:
                            if protocol in content.lower():
                                insecure_services.append((
                                    os.path.relpath(file_path, directory),
                                    f"{protocol.upper()} protocol detected"
                                ))
                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {str(e)}")
                    continue
    
    return insecure_services



# Helper functions
def extract_context(content: str, keyword: str, window: int = 50) -> str:
    """
    Extract context around found keyword
    
    Args:
        content: Text content to search in
        keyword: Keyword to find
        window: Number of characters to include before and after the keyword
        
    Returns:
        String with context around the keyword
    """
    idx = content.lower().find(keyword)
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end = min(len(content), idx + window)
    return f"...{content[start:end]}..."

def highlight_context(content: str, start: int, end: int) -> str:
    """
    Highlight matched content in context
    
    Args:
        content: Text content
        start: Start index of the match
        end: End index of the match
        
    Returns:
        String with highlighted context
    """
    context_start = max(0, start-30)
    context_end = min(len(content), end+30)
    context = content[context_start:context_end]
    match_text = content[start:end]
    return context.replace(match_text, f"**{match_text}**")

def detect_architecture_via_file(directory: str) -> Dict:
    """
    Detect architecture using file command
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        Dictionary with architecture information
    """
    for bin_path in Path(directory).rglob('*'):
        if bin_path.is_file() and bin_path.suffix in {'.so', '.ko', '.bin'}:
            try:
                result = subprocess.run(
                    ['file', str(bin_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False  # Don't raise exception on non-zero exit
                )
                if result.returncode == 0:
                    if 'ARM' in result.stdout:
                        return {'architecture': 'ARM'}
                    elif 'x86' in result.stdout:
                        return {'architecture': 'x86_64'}
            except Exception as e:
                logger.debug(f"Error using file command on {bin_path}: {str(e)}")
                continue
    return {'architecture': 'Unknown'}

def scan_binary_for_creds(bin_path: Path, directory: str) -> List[Tuple]:
    """
    Scan binary for credentials using strings
    
    Args:
        bin_path: Path to the binary file
        directory: Base directory for relative path calculation
        
    Returns:
        List of tuples with credential findings
    """
    try:
        result = subprocess.run(
            ['strings', str(bin_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False  # Don't raise exception on non-zero exit
        )
        if result.returncode == 0:
            return [
                (str(bin_path.relative_to(directory)), 
                highlight_context(result.stdout, m.start(), m.end()))
                for m in CRED_PATTERNS.finditer(result.stdout)
            ]
    except Exception as e:
        logger.debug(f"Error scanning binary {bin_path}: {str(e)}")
    return []   

def run_binwalk_in_wsl(file_path, extraction_dir):
    """Runs binwalk inside WSL and extracts firmware."""
    try:
        # First, try to extract the ZIP file directly
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(extraction_dir)
            logger.info(f"Extracted ZIP contents to {extraction_dir}")
            
        # List extracted files
        extracted_files = []
        for root, dirs, files in os.walk(extraction_dir):
            for file in files:
                extracted_files.append(os.path.join(root, file))
        
        logger.info(f"Extracted {len(extracted_files)} files")
        return True

    except zipfile.BadZipFile:
        # If it's not a ZIP or extraction fails, try binwalk
        try:
            wsl_file_path = file_path.replace("\\", "/")
            wsl_extraction_dir = extraction_dir.replace("\\", "/")
            
            command = f"wsl binwalk --extract --directory={wsl_extraction_dir} {wsl_file_path}"
            logger.info(f"Running binwalk command: {command}")
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=1800
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Binwalk extraction failed: {result.stderr}")
            
            logger.info(f"Binwalk output: {result.stdout[:500]}...")
            return True
            
        except Exception as e:
            logger.error(f"Extraction failed: {str(e)}")
            raise RuntimeError(f"Firmware extraction failed: {str(e)}")

def check_system_resources():
    """
    Check if system has sufficient resources for analysis
    """
    try:
        # Check for WSL and binwalk with increased timeout
        try:
            # Test WSL with longer timeout
            result = subprocess.run(
                "wsl ls /",  # Simple command to test WSL
                shell=True,
                capture_output=True,
                text=True,
                timeout=30  # Increased timeout to 30 seconds
            )
            
            if result.returncode != 0:
                raise RuntimeError("WSL is not responding properly")
            
            # Check if binwalk is installed in WSL
            result = subprocess.run(
                "wsl binwalk --help",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise RuntimeError("Binwalk not installed in WSL. Please install it using: wsl sudo apt-get install binwalk")
            
            logger.info("WSL and binwalk check passed successfully")
            
        except subprocess.TimeoutExpired:
            logger.error("WSL commands timed out. WSL might be starting up or not responding")
            raise RuntimeError("WSL is not responding. Please try again in a few moments")
        except subprocess.SubprocessError as e:
            logger.error(f"WSL/Binwalk check failed: {str(e)}")
            raise RuntimeError("WSL or binwalk check failed. Please ensure WSL is installed and running")
        
        # Check system resources
        if psutil.virtual_memory().available < 500 * 1024 * 1024:  # 500MB
            raise RuntimeError("Insufficient system memory")
            
        if psutil.cpu_percent(1) > 90:
            raise RuntimeError("System CPU overloaded")
        
        return True
            
    except Exception as e:
        logger.error(f"System check failed: {str(e)}")
        raise


 

def background_analysis(task_data):
    """
    Handle firmware analysis with proper error handling and cleanup
    
    Args:
        task_data: Dictionary with task information
        
    Returns:
        Dictionary with analysis results
    """
    task_id = task_data['task_id']
    extraction_dir = task_data['extraction_dir']
    temp_dir = task_data['temp_dir']
    start_time = datetime.now()

    try:
        # Use app context if available
        if 'app' in globals():
            with app.app_context():
                return _perform_analysis(task_data, task_id, extraction_dir, temp_dir, start_time)
        else:
            return _perform_analysis(task_data, task_id, extraction_dir, temp_dir, start_time)
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        with task_lock:
            background_tasks[task_data['task_id']] = {
                'status': 'failed',
                'error': str(e),
                'failed_at': datetime.now().isoformat()
            }
        return {"status": "error", "message": str(e)}
    finally:
        def delayed_cleanup(temp_dir):
            time.sleep(300)  # Keep files for 5 minutes
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

        threading.Thread(target=delayed_cleanup, args=(temp_dir,)).start()

def _perform_analysis(task_data, task_id, extraction_dir, temp_dir, start_time):
    """Internal function to perform the actual analysis"""
    logger.info(f"🚀 Starting analysis task {task_id}")
    analysis = {}

    try:
        # Initial system check
        check_system_resources()

        # Extract the firmware
        logger.info("⚙ Starting firmware extraction")
        run_binwalk_in_wsl(task_data['temp_path'], extraction_dir)
        
        # Verify extraction succeeded
        extracted_files = []
        for root, _, files in os.walk(extraction_dir):
            for file in files:
                extracted_files.append(os.path.join(root, file))
                
        if not extracted_files:
            raise RuntimeError("No files extracted - possibly invalid firmware")
        logger.info(f"✅ Extracted {len(extracted_files)} files")

        # Perform analysis steps with debug logging
        logger.info("Starting hardcoded credentials scan...")
        analysis['hardcoded_creds'] = find_hardcoded_creds(extraction_dir)
        logger.info(f"Found {len(analysis['hardcoded_creds'])} hardcoded credentials")
        
        logger.info("Starting insecure protocols scan...")
        analysis['insecure_protocols'] = find_insecure_protocols(extraction_dir)
        logger.info(f"Found {len(analysis['insecure_protocols'])} insecure protocols")
        
        logger.info("Starting weak encryption scan...")
        analysis['weak_encryption'] = find_weak_encryption(extraction_dir)
        logger.info(f"Found {len(analysis['weak_encryption'])} weak encryption instances")
        
        logger.info("Analyzing file structure...")
        analysis['file_structure'] = analyze_file_structure(extraction_dir)
        
        logger.info("Extracting metadata...")
        analysis['metadata'] = extract_firmware_metadata(extraction_dir)
        
        logger.info("Scanning for debug symbols...")
        analysis['debug_symbols'] = find_debug_symbols(extraction_dir)
        logger.info(f"Found {len(analysis['debug_symbols'])} debug symbols")
        

        logger.info("Scanning for outdated libraries...")
        analysis['lib_issues'] = find_lib_issues(extraction_dir)
        logger.info(f"Found {len(analysis['lib_issues'])} outdated libraries")
        analysis['ssl_libs'] = [lib for lib in analysis['lib_issues'] if lib.get('type') == 'ssl']


        logger.info("Checking for CVE vulnerabilities...")
        cve_results = check_cve_versions(analysis['ssl_libs'])  # Now correctly references ssl_libs
        logger.info(f"Found {len(cve_results)} CVE vulnerabilities")
        

        logger.info("Scanning for insecure services...")
        analysis['insecure_services'] = find_insecure_services(extraction_dir)
        logger.info(f"Found {len(analysis['insecure_services'])} insecure services")


        # Calculate risk score
        risk_score = 0
        risk_counts = {
            'critical': len(analysis.get('hardcoded_creds', [])) + len(analysis.get('insecure_services', [])),
            'high': len(analysis.get('weak_encryption', [])),
            'medium': len(analysis.get('lib_issues', [])) + len(analysis.get('debug_symbols', [])),
            'low': 1 if analysis.get('metadata') else 0
        }
        if analysis.get('hardcoded_creds'):
            risk_counts['critical'] += len(analysis['hardcoded_creds'])
            risk_score += len(analysis['hardcoded_creds']) * 5

        if analysis.get('insecure_protocols'):
            risk_score += len(analysis['insecure_protocols']) * 3

        if analysis.get('weak_encryption'):
            risk_counts['high'] += len(analysis['weak_encryption'])
            risk_score += len(analysis['weak_encryption']) * 4

        if analysis.get('insecure_services'):
            risk_counts['critical'] += len(analysis['insecure_services'])
            risk_score += len(analysis['insecure_services']) * 5 


        if analysis.get('cve_findings'):
            risk_counts['critical'] += len([cve for cve in analysis['cve_findings'] if cve['severity'] == 'critical'])
            risk_counts['high'] += len([cve for cve in analysis['cve_findings'] if cve['severity'] == 'high'])
            risk_score += len(analysis['cve_findings']) * 4     

        if analysis.get('lib_issues'):
            risk_counts['medium'] += len(analysis['lib_issues'])
            risk_score += len(analysis['lib_issues']) * 2

        if analysis.get('debug_symbols'):
            risk_counts['medium'] += len(analysis['debug_symbols'])
            risk_score += len(analysis['debug_symbols']) * 1

        if analysis.get('metadata'):
            risk_counts['low'] += 1
            risk_score += 0.5

        # File structure info - Low (0.5 points)
        if analysis.get('file_structure'):
            risk_counts['low'] += 1
            risk_score += 0.5

        risk_percentage = min(100, int((risk_score / 25) * 100))  # Adjusted scaling
        logger.info(f"Risk score: {risk_score}, Risk percentage: {risk_percentage}%")
                    
        # Update task status
        with task_lock:
            background_tasks[task_id] = {
                'status': 'completed',
                'progress': 100,
                'results': analysis,
                'risk': {
                    'percentage': risk_percentage,
                    'critical': risk_counts['critical'],
                    'high': risk_counts['high'],
                    'medium': risk_counts['medium'],
                    'low': risk_counts['low']
                },
                'completed_at': datetime.now().isoformat()
            }
        
        logger.info(f"✅ Analysis completed in {(datetime.now() - start_time).total_seconds():.2f} seconds")
        return analysis

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        raise



@app.route('/firmware_scan', methods=['GET', 'POST'])
@login_required
def firmware_scan():
    # Initialize with default values
    results = {}
    risk_percentage = 0
    critical_count = 0
    high_count = 0
    medium_count = 0  # Add this
    low_count = 0 
    scan_error = None
    task_id = request.args.get('task_id')

    # Check for existing completed task
    if task_id:
        with task_lock:
            task = background_tasks.get(task_id, {})
            if task.get('status') == 'completed':
                results = task.get('results', {})
                risk_data = task.get('risk', {})
                risk_percentage = risk_data.get('percentage', 0)
                critical_count = risk_data.get('critical', 0)
                high_count = risk_data.get('high', 0)
                medium_count = risk_data.get('medium', 0)  # Add these lines
                low_count = risk_data.get('low', 0)

            elif task.get('status') == 'failed':
                scan_error = task.get('error', 'Unknown error')

    # Handle download request
    if request.args.get('download') == 'true' and task_id:
        try:
            with task_lock:
                task = background_tasks.get(task_id, {})
            
            if not task or task.get('status') != 'completed':
                flash('No completed analysis found for download', 'error')
                return redirect(url_for('firmware_scan'))
            
            results = task.get('results', {})
            json_data = json.dumps(results, indent=2)
            
            response = make_response(json_data)
            response.headers['Content-Disposition'] = f'attachment; filename=firmware_analysis_{task_id}.json'
            response.headers['Content-Type'] = 'application/json'
            return response
        except Exception as e:
            logger.error(f"Download failed: {str(e)}")
            flash(f"Failed to download results: {str(e)}", 'error')
            return redirect(url_for('firmware_scan'))

    if request.method == 'POST':
        # Handle file upload
        if 'firmware' not in request.files:
            flash('No file uploaded', 'error')
            return render_template('firmware_scan.html',
                username=current_user.username,
                results=results,
                risk_percentage=risk_percentage,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                scan_error=scan_error,
                task_id=task_id
            )

        file = request.files['firmware']
        if not file or file.filename == '':
            flash('No file selected', 'error')
            return render_template('firmware_scan.html',
                username=current_user.username,
                results=results,
                risk_percentage=risk_percentage,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                scan_error=scan_error,
                task_id=task_id
            )

        try:
            # Validate file size
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            if file_size > 500 * 1024 * 1024:
                raise ValueError("File exceeds 500MB limit")

            # Create temp directory
            task_id = str(uuid.uuid4())
            temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"fw_{task_id}")
            os.makedirs(temp_dir, exist_ok=True)

            # Save file
            filename = secure_filename(file.filename)
            temp_path = os.path.join(temp_dir, filename)
            file.save(temp_path)
            
            # Initialize and store task
            with task_lock:
                background_tasks[task_id] = {
                    'status': 'queued',
                    'start_time': datetime.now().isoformat(),
                    'progress': 0,
                    'temp_dir': temp_dir
                }

            # Store task ID in session for persistence
            session['firmware_task_id'] = task_id

            # Start background task
            task_data = {
                'task_id': task_id,
                'temp_path': temp_path,
                'extraction_dir': os.path.join(temp_dir, 'extracted'),
                'temp_dir': temp_dir
            }
            threading.Thread(
                target=background_analysis,
                args=(task_data,),
                daemon=True
            ).start()

            # Handle AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    "status": "success",
                    "task_id": task_id,
                    "results_url": url_for('firmware_scan', task_id=task_id)
                })

            return redirect(url_for('firmware_scan', task_id=task_id))

        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"status": "error", "message": str(e)}), 400
            flash(str(e), 'error')
            return redirect(url_for('firmware_scan'))

    # GET request - show results if available
    return render_template('firmware_scan.html',
        username=current_user.username,
        results=results,
        risk_percentage=risk_percentage,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        scan_error=scan_error,
        task_id=task_id
    )
    

@app.route('/firmware_scan_status/<task_id>')
@login_required
def firmware_scan_status(task_id):
    try:
        with task_lock:
            task = background_tasks.get(task_id, {}).copy()
        
        # Add a flag to indicate if polling should stop
        if task.get('status') in ['completed', 'failed']:
            task['stop_polling'] = True
        
        # Add timestamp to prevent browser caching
        task['timestamp'] = datetime.now().isoformat()
        
        return jsonify(task)
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "stop_polling": True
        }), 500



@app.route('/analyze_traffic')
@login_required
def analyze_traffic_route():
    return render_template('traffic.html', username=current_user.username)

@app.route('/download_packet_sniffer')
@login_required
def download_packet_sniffer():
    try:
        return send_file(
            'packet_sniffer.py',
            as_attachment=True,
            download_name='packet_sniffer.py',
            mimetype='text/x-python'
        )
    except Exception as e:
        logger.error(f"Failed to download packet sniffer: {str(e)}", exc_info=True)
        flash('Failed to download packet sniffer', 'error')
        return redirect(url_for('analyze_traffic_route'))

# Load trained model and preprocessing components
try:
    model = joblib.load('rf_model.pkl')
    scaler = joblib.load('scaler.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
    
    # Define your new LABEL_MAPPING based on the output
    LABEL_MAPPING = {
        0: "Backdoor_Malware",
        1: "BenignTraffic",
        2: "BrowserHijacking",
        3: "CommandInjection",
        4: "DDoS-ACK_Fragmentation",
        5: "DDoS-HTTP_Flood",
        6: "DDoS-ICMP_Flood",
        7: "DDoS-ICMP_Fragmentation",
        8: "DDoS-PSHACK_Flood",
        9: "DDoS-RSTFINFlood",
        10: "DDoS-SYN_Flood",
        11: "DDoS-SlowLoris",
        12: "DDoS-SynonymousIP_Flood",
        13: "DDoS-TCP_Flood",
        14: "DDoS-UDP_Flood",
        15: "DDoS-UDP_Fragmentation",
        16: "DNS_Spoofing",
        17: "DictionaryBruteForce",
        18: "DoS-HTTP_Flood",
        19: "DoS-SYN_Flood",
        20: "DoS-TCP_Flood",
        21: "DoS-UDP_Flood",
        22: "MITM-ArpSpoofing",
        23: "Mirai-greeth_flood",
        24: "Mirai-greip_flood",
        25: "Mirai-udpplain",
        26: "Recon-HostDiscovery",
        27: "Recon-OSScan",
        28: "Recon-PingSweep",
        29: "Recon-PortScan",
        30: "SqlInjection",
        31: "Uploading_Attack",
        32: "VulnerabilityScan",
        33: "XSS"
    }
    
    
    # For option 1, keep the existing train_columns if they match what your model expects
    train_columns = ['flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
                      'rst_flag_number', 'psh_flag_number', 'ack_flag_number', 'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count',
                        'fin_count', 'urg_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP',
                          'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance',
                            'Variance', 'Weight']
    
    logger.info("Successfully loaded ML model and preprocessing components")
except Exception as e:
    logger.error(f"Failed to load ML model: {str(e)}", exc_info=True)
    model = None
    scaler = None
    label_encoder = None
    LABEL_MAPPING = {}
    train_columns = []

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file uploaded.', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)

        if not model or not scaler:
            flash('ML model not available. Please contact the administrator.', 'error')
            return redirect(request.url)

        # Create a unique filename
        filename = str(uuid.uuid4()) + '.csv'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(file_path)
            
            # Load CSV
            df_test = pd.read_csv(file_path)
            df_test.columns = df_test.columns.str.strip()  # Clean column names

            # Ensure test data has the same columns
            train_columns_cleaned = [col.strip() for col in train_columns]
            
            # Check if columns exist in the uploaded file
            missing_columns = [col for col in train_columns_cleaned if col not in df_test.columns]
            if missing_columns:
                raise ValueError(f"Missing required columns in uploaded file: {', '.join(missing_columns)}")
            
            # Select only the needed columns in the correct order
            df_test = df_test[train_columns_cleaned]

            # Scale features
            X_test = scaler.transform(df_test)

            # Perform batch-wise predictions
            batch_size = 100000
            predictions = []
            for start in range(0, X_test.shape[0], batch_size):
                end = min(start + batch_size, X_test.shape[0])
                batch = X_test[start:end]
                batch_predictions = model.predict(batch)
                predictions.extend(batch_predictions)

            # Map predictions to labels
            df_test['Predicted_Label'] = predictions
            df_test['Predicted_Attack'] = df_test['Predicted_Label'].map(LABEL_MAPPING)

            # Save labeled results
            results_path = os.path.join(app.config['UPLOAD_FOLDER'], f"labeled_results_{current_user.id}.csv")
            df_test.to_csv(results_path, index=False)

            # Count attack occurrences
            attack_counts = df_test['Predicted_Attack'].value_counts().to_dict()
            print(f"attack_counts: {attack_counts}")

            # Store results in session
            session['analysis_results'] = {
                'file_path': results_path,
                'attack_counts': attack_counts,
                'timestamp': datetime.now().isoformat()
            }

            return render_template(
                'upload.html', 
                username=current_user.username, 
                results=df_test.head(20).to_dict(orient='records'),
                attack_counts=attack_counts, 
                label_mapping=LABEL_MAPPING
            )

        except Exception as e:
            logger.error(f"Error processing file: {str(e)}", exc_info=True)
            flash(f'Error processing file: {str(e)}', 'error')

        finally:
            # Clean up the uploaded file
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.error(f"Failed to remove temporary file: {str(e)}", exc_info=True)

    return render_template('upload.html', username=current_user.username, attack_counts={})


@app.route('/upload_vuln_scan', methods=['POST'])
@login_required
def upload_vuln_scan():
    if 'vuln-file' not in request.files:
        return jsonify({"status": "error", "error": "No file uploaded"}), 400
        
    file = request.files['vuln-file']
    if file.filename == '':
        return jsonify({"status": "error", "error": "Empty filename"}), 400

    try:
        # Get file size and check if it's too large
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 10 * 1024 * 1024:  # 10 MB limit
            return jsonify({"status": "error", "error": "File too large (max 10MB)"}), 413
        
        # Read the content of the file
        content = file.read().decode('utf-8', errors='replace')
        
        # Log file size and initial parsing
        logger.info(f"Processing vulnerability scan file: {file.filename}, size: {file_size} bytes")
        
        # Extract CVEs using the improved patterns
        cve_data = extract_cves_from_scan(content)
        
        # Log extracted CVEs count
        logger.info(f"Extracted {len(cve_data)} CVEs from scan file")
        
        # Store in session
        session['uploaded_cves'] = cve_data
        
        return jsonify({"status": "success", "count": len(cve_data)})
    except Exception as e:
        logger.error(f"Error processing vulnerability scan: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "error": f"Failed to process file: {str(e)}"}), 500
    

def extract_cves_from_scan(scan_content: str) -> List[Dict[str, Any]]:
    """
    Enhanced CVE extraction function for security scan results.
    This function properly extracts CVE IDs, severity scores, vulnerability states,
    and descriptions from Nmap vulnerability scan output.
    
    Args:
        scan_content: The raw text content from a vulnerability scan
        
    Returns:
        A list of dictionaries containing CVE details
    """
    # Initialize data structures
    cve_data = []
    cve_map = {}
    
    # Step 1: Extract all CVE IDs using various patterns
    cve_patterns = [
        # Format: CVE-YYYY-NNNNN
        r'CVE-(\d{4}-\d{1,7})',
        
        # Format: CVE:YYYY-NNNNN or CVE: YYYY-NNNNN
        r'CVE:[ ]?(\d{4}-\d{1,7})',
        
        # Format with IDs field: IDs: ... CVE:CVE-YYYY-NNNNN
        r'IDs:.*?CVE:CVE-(\d{4}-\d{1,7})',
        
        # Format with IDs field: IDs: ... CVE-YYYY-NNNNN
        r'IDs:.*?CVE[-:](\d{4}-\d{1,7})',
        
        # Format in nmap: http-vuln-cveYYYY-NNNNN
        r'http-vuln-cve(\d{4}-\d{1,7})',
        
        # Format in vulners output: CVE-YYYY-NNNNN tab score tab URL
        r'CVE-(\d{4}-\d{1,7})\t'
    ]
    
    # Extract all CVE IDs first
    for pattern in cve_patterns:
        for match in re.finditer(pattern, scan_content, re.IGNORECASE):
            # Normalize the ID format
            normalized_id = f"CVE-{match.group(1)}"
            
            # Only add if not already in our map
            if normalized_id not in cve_map:
                cve_obj = {
                    'cve_id': normalized_id,
                    'severity': None,
                    'state': None,
                    'description': None
                }
                
                cve_map[normalized_id] = cve_obj
                cve_data.append(cve_obj)
    
    # Step 2: Extract severity information (CVSS scores)
    # Pattern for CVEs with CVSS scores (usually in Vulners output)
    severity_pattern = r'CVE-(\d{4}-\d{1,7})\s+(\d+\.\d+)'
    
    for match in re.finditer(severity_pattern, scan_content):
        normalized_id = f"CVE-{match.group(1)}"
        severity = float(match.group(2))
        
        if normalized_id in cve_map:
            cve_map[normalized_id]['severity'] = severity
    
    # Step 3: Extract vulnerability state information
    # Find VULNERABLE sections and associate with CVEs
    vulnerable_pattern = r'^\s*(VULNERABLE|LIKELY VULNERABLE):?\s*([\s\S]*?)(?=^\s*(?:VULNERABLE|LIKELY VULNERABLE|References:|$))'
    
    for match in re.finditer(vulnerable_pattern, scan_content, re.MULTILINE):
        state = match.group(1)
        section_content = match.group(2)
        
        # Look for CVEs in this section
        cve_in_section_pattern = r'CVE[-:](\d{4}-\d{1,7})'
        
        for cve_match in re.finditer(cve_in_section_pattern, section_content):
            cve_id = f"CVE-{cve_match.group(1)}"
            
            if cve_id in cve_map:
                cve_map[cve_id]['state'] = state
                
                # Try to find a description within this vulnerability section
                if not cve_map[cve_id]['description']:
                    # Most vulnerability sections place descriptions after the CVE ID and on next lines
                    desc_pattern = fr'{cve_id.replace("-", "[-:]")}[^\n]*\n\s*([^\n]{{10,}})'
                    desc_match = re.search(desc_pattern, section_content, re.DOTALL)
                    
                    if desc_match and desc_match.group(1) and \
                       not re.match(r'\s*CVE[-:]', desc_match.group(1), re.IGNORECASE) and \
                       'http://' not in desc_match.group(1):
                        cve_map[cve_id]['description'] = desc_match.group(1).strip()
    
    # Step 4: Extract descriptions for CVEs in IDs sections
    for cve in cve_data:
        if not cve['description']:
            id_pattern = fr'IDs:.*?{cve["cve_id"].replace("-", "[-:]")}[^\n]*\n\s*([^\n]{{10,}})'
            id_match = re.search(id_pattern, scan_content, re.DOTALL)
            
            if id_match and id_match.group(1) and \
               not re.match(r'\s*CVE[-:]', id_match.group(1), re.IGNORECASE) and \
               'http://' not in id_match.group(1):
                cve['description'] = id_match.group(1).strip()
    
    # Step 5: Try another pass for missing descriptions with a more generic approach
    for cve in cve_data:
        if not cve['description']:
            # Look for descriptions after the CVE ID
            general_desc_pattern = fr'{cve["cve_id"]}\s+([^\n]{{10,}}[^\s])'
            general_match = re.search(general_desc_pattern, scan_content, re.DOTALL)
            
            if general_match and general_match.group(1) and \
               not re.match(r'\s*CVE[-:]', general_match.group(1), re.IGNORECASE) and \
               'http://' not in general_match.group(1) and \
               not re.match(r'^\d+\.\d+\s+https', general_match.group(1)):
                cve['description'] = general_match.group(1).strip()
    
    # Step 6: Clean up descriptions that are actually references to other CVEs
    for cve in cve_data:
        if cve['description']:
            # Clean up descriptions that are actually references to other CVEs or URLs
            if re.match(r'\s*CVE[-:]', cve['description'], re.IGNORECASE) or \
               'https://vulners.com/' in cve['description'] or \
               'https://cve.mitre.org/' in cve['description'] or \
               '*EXPLOIT*' in cve['description'] or \
               re.match(r'^\d+\.\d+\s+', cve['description']):
                cve['description'] = None
    
    return cve_data


@app.route('/get_uploaded_cves')
@login_required
def get_uploaded_cves():
    """
    Return the CVEs extracted from the user's uploaded scan file.
    If descriptions are missing, try to fill them from our predefined mappings.
    """
    uploaded_cves = session.get('uploaded_cves', [])
    
    if not uploaded_cves:
        return jsonify([])
    
    # Make sure all CVEs have complete information
    for cve in uploaded_cves:
        # Ensure we have at least a description field
        if 'description' not in cve or not cve['description']:
            # Try to find this CVE in our predefined mappings
            for attack, cves in attack_cve_map.items():
                for predefined_cve in cves:
                    if predefined_cve['cve_id'].upper() == cve['cve_id'].upper():
                        cve['description'] = predefined_cve.get('description', 'No description available')
                        break
                        
        # If still no description, set a default one
        if not cve.get('description'):
            cve['description'] = "Vulnerability information not available"
    
    return jsonify(uploaded_cves)

@app.route('/clear_uploaded_cves', methods=['POST'])
@login_required
def clear_uploaded_cves():
    """Clear uploaded CVEs from session"""
    try:
        if 'uploaded_cves' in session:
            session.pop('uploaded_cves')
            session.modified = True
        return jsonify({"status": "success", "message": "Uploaded CVEs cleared"})
    except Exception as e:
        logger.error(f"Error clearing uploaded CVEs: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500
    
@app.route('/get_cve_mappings')
@login_required
def get_cve_mappings():
    return jsonify(attack_cve_map)

@app.route('/cve_details/<cve_id>')
@login_required
def cve_details(cve_id):
    # Search all mappings for the specific CVE
    for attack, cves in attack_cve_map.items():
        for cve in cves:
            if cve['cve_id'].lower() == cve_id.lower():
                return jsonify(cve)
    return jsonify({"error": "CVE not found"}), 404


@app.route('/get_attack_counts')
@login_required
def get_attack_counts():
    """Return the attack counts from the current analysis results"""
    results_info = session.get('analysis_results')
    if not results_info or 'attack_counts' not in results_info:
        return jsonify({})
        
    # Normalize attack names to ensure consistent lookup
    normalized_counts = {}
    for attack, count in results_info['attack_counts'].items():
        normalized_attack = attack.replace(' ', '_').replace('-', '_').upper()
        normalized_counts[normalized_attack] = count
        
    return jsonify(normalized_counts)

@app.route('/get_correlation_results')
def get_correlation_results():
    # Return processed correlation data from session/database
    return jsonify(session.get('correlation_data', []))

@app.route('/get_remediation_data')
def get_remediation_data():
    # Return structured remediation data
    return jsonify([
        {
            'title': 'DDoS Protection',
            'severity': 'Critical',
            'steps': ['Implement rate limiting', 'Configure firewalls']
        },
        # Add other remediation items
    ])

@app.route('/use_default_cves', methods=['POST'])
@login_required
def use_default_cves():
    """Use default CVE mappings when user skips upload"""
    try:
        # Clear any existing uploaded CVEs first
        if 'uploaded_cves' in session:
            session.pop('uploaded_cves')
        
        # Set a flag to indicate we're using default CVEs
        session['use_default_cves'] = True
        session.modified = True
        
        return jsonify({"status": "success", "message": "Using default CVE mappings"})
    except Exception as e:
        logger.error(f"Error setting default CVEs: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/download_results')
@login_required
def download_results():
    results_info = session.get('analysis_results')
    
    if not results_info or 'file_path' not in results_info:
        flash('No analysis results available. Please upload a file first.', 'error')
        return redirect(url_for('upload_file'))
    
    file_path = results_info['file_path']
    
    if not os.path.exists(file_path):
        flash('Results file not found. It may have expired.', 'error')
        return redirect(url_for('upload_file'))
    
    try:
        return send_file(
            file_path,
            mimetype='text/csv',
            as_attachment=True,
            download_name='traffic_analysis_results.csv'
        )
    except Exception as e:
        logger.error(f"Failed to download results: {str(e)}", exc_info=True)
        flash('Failed to download results', 'error')
        return redirect(url_for('upload_file'))

@app.route('/alert-settings', methods=['GET', 'POST'])
@login_required
def alert_settings():
    user = current_user
    
    if request.method == 'POST':
        # Get the state of the toggle switch
        account_alerts = request.form.get('account-alerts') == 'on'
        
        # Update the user's alert settings in the database
        user.account_alerts_enabled = account_alerts
        db.session.commit()
        
        logger.info(f"Updated account alerts for user {user.username} to {account_alerts}")
        flash('Alert settings updated successfully!', 'success')
        return redirect(url_for('alert_settings'))

    return render_template('alert_settings.html', username=user.username, email=user.email)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = current_user
    
    if request.method == 'POST':
        new_username = request.form.get('new_username')
        if new_username:
            # Check if the new username is already taken
            if User.query.filter_by(username=new_username).first() and new_username != user.username:
                flash('This username is already taken. Please choose a different username.', 'error')
            else:
                old_username = user.username
                user.username = new_username
                db.session.commit()
                session['username'] = new_username
                logger.info(f"Username changed from {old_username} to {new_username}")
                flash('Username updated successfully!', 'success')
        return redirect(url_for('account'))

    return render_template('account.html', username=user.username, email=user.email)    

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        # Handle form submission for settings
        theme = request.form.get('theme')
        language = request.form.get('language')
        default_scan_range = request.form.get('default-scan-range')
        device_naming = request.form.get('device-naming')

        # Save settings to the session
        session['theme'] = theme
        session['language'] = language
        session['default_scan_range'] = default_scan_range
        session['device_naming'] = device_naming

        flash('Settings saved successfully!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', username=current_user.username)

@app.route('/feedback', methods=['POST'])
@login_required
def feedback():
    if request.method == 'POST':
        feedback_message = request.form.get('feedback')
        if feedback_message:
            # Create feedback directory if it doesn't exist
            feedback_dir = 'feedback'
            if not os.path.exists(feedback_dir):
                os.makedirs(feedback_dir)
                
            # Save feedback to a file with timestamp and username
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            filename = os.path.join(feedback_dir, f"feedback_{timestamp}_{current_user.username}.txt")
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"User: {current_user.username}\n")
                f.write(f"Email: {current_user.email}\n")
                f.write(f"Time: {timestamp}\n")
                f.write(f"Feedback: {feedback_message}\n")
            
            logger.info(f"Feedback received from {current_user.username}")
            flash('Thank you for your feedback!', 'success')
        else:
            flash('Feedback cannot be empty.', 'error')
        
        return redirect(url_for('settings'))

@app.route('/download-user-guide')
def download_user_guide():
    try:
        return send_file(
            'static/user_guide.pdf',
            as_attachment=True,
            download_name='iot_tracker_user_guide.pdf',
            mimetype='application/pdf'
        )
    except Exception as e:
        logger.error(f"Failed to download user guide: {str(e)}", exc_info=True)
        flash('Failed to download user guide', 'error')
        return redirect(url_for('index'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {str(e)}", exc_info=True)
    return render_template('errors/500.html'), 500


@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

# Register template filter for base64 encoding
@app.template_filter('b64encode')
def b64encode_filter(s):
    if isinstance(s, str):
        s = s.encode('utf-8')
    return base64.b64encode(s).decode('utf-8')

# Cleanup task for expired background tasks
def cleanup_expired_tasks():
    with task_lock:
        current_time = datetime.now()
        tasks_to_remove = []
        
        for task_id, task in background_tasks.items():
            # Check for completed tasks older than 24 hours
            if task.get('status') == 'completed' and 'completed_at' in task:
                completed_time = datetime.fromisoformat(task['completed_at'])
                if (current_time - completed_time) > timedelta(hours=24):
                    tasks_to_remove.append(task_id)
                    
                    # Remove associated files
                    if 'file' in task and os.path.exists(task['file']):
                        try:
                            os.remove(task['file'])
                        except Exception as e:
                            logger.error(f"Failed to remove file: {str(e)}", exc_info=True)
            
            # Check for failed tasks older than 1 hour
            elif task.get('status') == 'failed' and 'failed_at' in task:
                failed_time = datetime.fromisoformat(task['failed_at'])
                if (current_time - failed_time) > timedelta(hours=1):
                    tasks_to_remove.append(task_id)
        
        # Remove expired tasks
        for task_id in tasks_to_remove:
            background_tasks.pop(task_id, None)
            logger.info(f"Removed expired task: {task_id}")

# Schedule cleanup task to run periodically
def schedule_cleanup():
    cleanup_expired_tasks()
    threading.Timer(3600, schedule_cleanup).start()  # Run every hour

# Alternative approach for Flask 2.3.0+ (no before_first_request)
def init_app(app):
    with app.app_context():
        # Start the cleanup scheduler
        schedule_cleanup()

# Run the application
if __name__ == '__main__':
    check_wsl_availability()
    # Initialize the app
    init_app(app)
    
    # In production, use a proper WSGI server like Gunicorn or uWSGI
    if DEBUG:
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        app.run(debug=False, host='0.0.0.0', port=5000)



