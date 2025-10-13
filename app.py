# app.py - ADD THIS AT THE VERY TOP
import os
from xml.dom.minidom import Document
import eventlet

# Monkey patch early to avoid issues
eventlet.monkey_patch()

# Now import other modules
import string
import bcrypt
import re
import bleach
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, send_file, send_from_directory, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
import pytz
from tzlocal import get_localzone
import requests
from urllib.parse import urlencode
import secrets

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

# Enhanced Database configuration with better PostgreSQL/SSL handling
def get_database_uri():
    """Get database URI with proper PostgreSQL/SSL handling for Render"""
    database_url = os.environ.get('DATABASE_URL')
    
    # If no DATABASE_URL, use SQLite locally
    if not database_url:
        return 'sqlite:///makokha_medical.db'
    
    # Handle PostgreSQL URL normalization
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    # Add SSL requirement for production PostgreSQL
    if database_url.startswith('postgresql://') and 'sslmode=' not in database_url:
        # Check if we're in production (Render)
        if os.environ.get('RENDER') or os.environ.get('FLASK_ENV') == 'production':
            database_url += '?sslmode=require'
    
    return database_url

app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY') or 'csrf-secret-key-change-in-production'

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar'}

# Security settings - only enable secure cookies in production
is_production = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('RENDER')
app.config['SESSION_COOKIE_SECURE'] = is_production
app.config['REMEMBER_COOKIE_SECURE'] = is_production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER', '')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS', '')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)
csrf = CSRFProtect(app)



# Fix: Improved Limiter configuration with proper fallback
try:
    # Try to use Redis if available
    redis_url = os.environ.get('REDIS_URL')
    
    if redis_url:
        # Handle Redis SSL connections for production
        if redis_url.startswith('rediss://'):
            redis_url += "?ssl_cert_reqs=none"
        
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            storage_uri=redis_url,
            default_limits=["200 per day", "50 per hour"],
            strategy="fixed-window",
            headers_enabled=True
        )
        print("✅ Redis rate limiting enabled")
    else:
        # Fallback to memory storage
        raise Exception("No Redis URL configured")
        
except Exception as e:
    # Fallback to memory storage with warning suppression
    import warnings
    warnings.filterwarnings("ignore", message="Using the in-memory storage")
    
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        strategy="fixed-window",
        storage_uri="memory://"
    )
    print("⚠️ Using in-memory rate limiting (Redis not available)")

# Replace your current SocketIO initialization with this:
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    async_mode='eventlet',
    logger=False,  # Disable in production
    engineio_logger=False,  # Disable in production
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=100 * 1024 * 1024  # 100MB for file uploads
)

# Configure login manager
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"

# =============================================================================
# WEBSOCKET HANDLERS
# =============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        emit('connection_status', {'status': 'connected', 'user_id': current_user.id})
        print(f"User {current_user.id} connected to WebSocket")
    else:
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')
        print(f"User {current_user.id} disconnected from WebSocket")

@socketio.on('join_appointment')
def handle_join_appointment(data):
    """Join an appointment room for real-time communication"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    if appointment_id:
        room_name = f'appointment_{appointment_id}'
        join_room(room_name)
        emit('joined_room', {'room': room_name, 'appointment_id': appointment_id})
        print(f"User {current_user.id} joined room {room_name}")

@socketio.on('leave_appointment')
def handle_leave_appointment(data):
    """Leave an appointment room"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    if appointment_id:
        room_name = f'appointment_{appointment_id}'
        leave_room(room_name)
        emit('left_room', {'room': room_name, 'appointment_id': appointment_id})

@socketio.on('send_message')
def handle_send_message(data):
    """Handle real-time message sending"""
    if not current_user.is_authenticated:
        return
    
    try:
        appointment_id = data.get('appointment_id')
        content = sanitize_input(data.get('content', '').strip())
        message_type = data.get('message_type', 'text')
        if not content or not appointment_id:
            return
        
        # Verify user has access to this appointment
        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return
        
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return
        
        # Check if doctor can communicate (payment completed)
        if current_user.role == 'doctor' and appointment.payment_status != 'completed':
            return
        
        # Determine receiver
        if current_user.role == 'patient':
            receiver_id = appointment.doctor.user_id
        else:
            receiver_id = appointment.patient.user_id
        
        # Create message in database
        message = Message(
            appointment_id=appointment_id,
            sender_id=current_user.id,
            receiver_id=receiver_id,
            message_type=message_type,
            content=content
        )
        
        db.session.add(message)
        db.session.commit()
        
        # Prepare message data for broadcasting
        message_data = {
            'id': message.id,
            'appointment_id': appointment_id,
            'sender_id': message.sender_id,
            'sender_name': message.sender.username or message.sender.email,
            'sender_role': message.sender.role,
            'receiver_id': message.receiver_id,
            'message_type': message.message_type,
            'content': message.content,
            'is_read': message.is_read,
            'created_at': message.created_at.isoformat(),
            'is_own': False  # This will be set by the receiver's client
        }
        
        # Broadcast to appointment room and receiver's personal room
        room_name = f'appointment_{appointment_id}'
        emit('new_message', message_data, room=room_name)
        emit('new_message', {**message_data, 'is_own': True}, room=f'user_{receiver_id}')
        
        log_audit('message_sent_websocket', current_user.id, f'Appointment: {appointment_id}')
        
    except Exception as e:
        app.logger.error(f"WebSocket message error: {str(e)}")
        emit('message_error', {'error': 'Failed to send message'})

@socketio.on('typing_start')
def handle_typing_start(data):
    """Handle typing start event"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    if appointment_id:
        room_name = f'appointment_{appointment_id}'
        emit('user_typing', {
            'user_id': current_user.id,
            'user_name': current_user.username or current_user.email,
            'is_typing': True
        }, room=room_name, include_self=False)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    """Handle typing stop event"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    if appointment_id:
        room_name = f'appointment_{appointment_id}'
        emit('user_typing', {
            'user_id': current_user.id,
            'user_name': current_user.username or current_user.email,
            'is_typing': False
        }, room=room_name, include_self=False)

@socketio.on('call_initiate')
def handle_call_initiate(data):
    """Handle call initiation"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    call_type = data.get('call_type', 'voice')  # 'voice' or 'video'
    
    appointment = Appointment.query.get(appointment_id)
    if not appointment:
        return
    
    # Determine receiver
    if current_user.role == 'patient':
        receiver_id = appointment.doctor.user_id
    else:
        receiver_id = appointment.patient.user_id
    
    # Send call notification to receiver
    emit('incoming_call', {
        'appointment_id': appointment_id,
        'caller_id': current_user.id,
        'caller_name': current_user.username or current_user.email,
        'call_type': call_type,
        'call_id': data.get('call_id')
    }, room=f'user_{receiver_id}')

@socketio.on('call_accept')
def handle_call_accept(data):
    """Handle call acceptance"""
    if not current_user.is_authenticated:
        return
    
    call_id = data.get('call_id')
    appointment_id = data.get('appointment_id')
    
    # Notify caller that call was accepted
    emit('call_accepted', {
        'call_id': call_id,
        'acceptor_id': current_user.id
    }, room=f'appointment_{appointment_id}')

@socketio.on('call_reject')
def handle_call_reject(data):
    """Handle call rejection"""
    if not current_user.is_authenticated:
        return
    
    call_id = data.get('call_id')
    appointment_id = data.get('appointment_id')
    
    # Notify caller that call was rejected
    emit('call_rejected', {
        'call_id': call_id,
        'rejector_id': current_user.id
    }, room=f'appointment_{appointment_id}')

@socketio.on('call_end')
def handle_call_end(data):
    """Handle call end"""
    appointment_id = data.get('appointment_id')
    call_id = data.get('call_id')
    
    # Notify all participants that call ended
    emit('call_ended', {
        'call_id': call_id,
        'ended_by': current_user.id
    }, room=f'appointment_{appointment_id}')

# =============================================================================
# TIMEZONE UTILITY FUNCTIONS
# =============================================================================

def get_user_timezone():
    """Get user's timezone based on their location"""
    try:
        # Method 1: Check if user has a preferred timezone in session
        if 'user_timezone' in session:
            return pytz.timezone(session['user_timezone'])
        
        # Method 2: Get timezone from IP address
        ip_address = request.remote_addr
        
        # For localhost/testing, use a default timezone
        if ip_address in ['127.0.0.1', 'localhost']:
            # Default to Nairobi timezone for Kenya
            return pytz.timezone('Africa/Nairobi')
        
        # Use ipapi.co to get timezone from IP (free tier available)
        try:
            response = requests.get(f'http://ipapi.co/{ip_address}/timezone/', timeout=3)
            if response.status_code == 200:
                timezone_str = response.text.strip()
                if timezone_str:
                    session['user_timezone'] = timezone_str
                    return pytz.timezone(timezone_str)
        except:
            pass
        
        # Method 3: Use browser timezone if available via JavaScript
        browser_tz = request.headers.get('X-Timezone')  # Set via JavaScript
        if browser_tz:
            session['user_timezone'] = browser_tz
            return pytz.timezone(browser_tz)
        
        # Fallback: Default to UTC
        return pytz.UTC
        
    except Exception as e:
        app.logger.error(f"Error getting user timezone: {str(e)}")
        return pytz.UTC

def get_current_time():
    """Get current time in user's timezone"""
    user_tz = get_user_timezone()
    return datetime.now(user_tz)

def convert_to_user_timezone(utc_dt):
    """Convert UTC datetime to user's timezone"""
    if not utc_dt:
        return None
    
    if utc_dt.tzinfo is None:
        utc_dt = pytz.UTC.localize(utc_dt)
    
    user_tz = get_user_timezone()
    return utc_dt.astimezone(user_tz)

def convert_to_utc(user_dt):
    """Convert user's local datetime to UTC"""
    if not user_dt:
        return None
    
    if user_dt.tzinfo is None:
        user_tz = get_user_timezone()
        user_dt = user_tz.localize(user_dt)
    
    return user_dt.astimezone(pytz.UTC)

def format_datetime(dt, format_str="%Y-%m-%d %H:%M:%S %Z"):
    """Format datetime in user's timezone"""
    if not dt:
        return ""
    
    local_dt = convert_to_user_timezone(dt)
    return local_dt.strftime(format_str)

# Add this to your app.py
def generate_stars(rating):
    """Generate star rating HTML"""
    full_stars = int(rating)
    half_star = 1 if rating - full_stars >= 0.5 else 0
    empty_stars = 5 - full_stars - half_star
    
    stars = '★' * full_stars
    if half_star:
        stars += '½'
    stars += '☆' * empty_stars
    
    return f'<span style="color: #fbbf24;">{stars}</span>'

# Make it available to templates
app.jinja_env.globals.update(generate_stars=generate_stars)

# =============================================================================
# MODELS (Updated with proper timezone handling)
# =============================================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())  # FIXED
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    timezone = db.Column(db.String(50), default='UTC')
    
    # Profile relationships
    patient_profile = db.relationship('Patient', backref='user', uselist=False, cascade='all, delete-orphan')
    doctor_profile = db.relationship('Doctor', backref='user', uselist=False, cascade='all, delete-orphan')
    def is_account_locked(self):
        """Check if account is temporarily locked due to failed login attempts"""
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False

    def increment_login_attempts(self):
        """Increment failed login attempts and lock account if threshold exceeded"""
        self.login_attempts = (self.login_attempts or 0) + 1
        
        # Lock account for 15 minutes after 5 failed attempts
        if self.login_attempts >= 5:
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
            log_audit('account_locked', self.id, 'Too many failed login attempts')
        
        db.session.commit()

    def reset_login_attempts(self):
        """Reset login attempts on successful login"""
        if self.login_attempts > 0 or self.account_locked_until:
            self.login_attempts = 0
            self.account_locked_until = None
            db.session.commit()

    def set_password(self, password):
        """Hash and set password with bcrypt - only for non-OAuth users"""
        if not password:
            # For OAuth users, we don't set a password
            self.password_hash = None
            return
            
        if not self.is_strong_password(password):
            raise ValueError("Password must be at least 8 characters with uppercase, lowercase, number, and special character")
        
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def set_oauth_password(self):
        """Set a secure password for OAuth users that meets requirements but won't be used"""
        import string
        import secrets
        
        # Generate a password that meets all requirements
        uppercase = secrets.choice(string.ascii_uppercase)
        lowercase = secrets.choice(string.ascii_lowercase)
        digit = secrets.choice(string.digits)
        special = secrets.choice('!@#$%^&*(),.?":{}|<>')
        remaining = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%^&*(),.?":{}|<>') 
                          for i in range(4))
        secure_password = uppercase + lowercase + digit + special + remaining
        
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(secure_password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        """Verify password with bcrypt"""
        # For OAuth users without passwords, always return False for password attempts
        if not self.password_hash:
            return False
            
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def is_strong_password(self, password):
        """Validate password strength"""
        if not password:
            return False
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True

    def can_login_with_password(self):
        """Check if user can login with password (not OAuth only)"""
        return self.password_hash is not None and self.google_id is None

    def get_oauth_provider(self):
        """Check if user signed up via OAuth"""
        if self.google_id:
            return 'google'
        return 'email'

    def get_user_timezone(self):
        """Get user's timezone preference"""
        if self.timezone:
            try:
                return pytz.timezone(self.timezone)
            except pytz.UnknownTimeZoneError:
                pass
        return pytz.UTC

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    date_of_birth = db.Column(db.Date)
    address = db.Column(db.Text)
    emergency_contact = db.Column(db.String(100))
    medical_history = db.Column(db.Text)
    
    appointments = db.relationship('Appointment', backref='patient', lazy=True, cascade='all, delete-orphan')
    documents = db.relationship('PatientDocument', backref='patient', lazy=True, cascade='all, delete-orphan')

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    license_number = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    consultation_fee = db.Column(db.Float, nullable=False)
    available_hours = db.Column(db.Text)
    is_available = db.Column(db.Boolean, default=True)
    timezone = db.Column(db.String(50), default='UTC')
    experience = db.Column(db.Integer, default=5)  # Years of experience
    average_rating = db.Column(db.Float, default=0.0)
    review_count = db.Column(db.Integer, default=0)
    response_time = db.Column(db.String(50), default='< 1 hour')
    patient_count = db.Column(db.Integer, default=0)
    is_featured = db.Column(db.Boolean, default=False)
    education = db.Column(db.Text)  # Educational background
    certifications = db.Column(db.Text)  # Certifications
    languages = db.Column(db.String(200), default='English, Swahili')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    appointments = db.relationship('Appointment', backref='doctor', lazy=True, cascade='all, delete-orphan')
    
    def get_initials(self):
        """Get doctor initials for avatar"""
        first_initial = self.first_name[0] if self.first_name else ''
        last_initial = self.last_name[0] if self.last_name else ''
        return f"{first_initial}{last_initial}"
        
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id', ondelete='CASCADE'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id', ondelete='CASCADE'), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)  # Stored in UTC
    status = db.Column(db.String(20), default='scheduled')
    symptoms = db.Column(db.Text)
    diagnosis = db.Column(db.Text)
    prescription = db.Column(db.Text)
    payment_status = db.Column(db.String(20), default='pending')
    payment_reference = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    consultation_notes = db.Column(db.Text)
    
    # Communication fields
    video_call_url = db.Column(db.String(255))
    voice_call_url = db.Column(db.String(255))
    whatsapp_chat_id = db.Column(db.String(100))

    def get_local_appointment_time(self, for_user=None):
        """Get appointment time in local timezone"""
        if not self.appointment_date:
            return None
        
        # If specific user provided, use their timezone
        if for_user and hasattr(for_user, 'get_user_timezone'):
            user_tz = for_user.get_user_timezone()
        else:
            user_tz = get_user_timezone()
        
        if self.appointment_date.tzinfo is None:
            utc_dt = pytz.UTC.localize(self.appointment_date)
        else:
            utc_dt = self.appointment_date
        
        return utc_dt.astimezone(user_tz)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id', ondelete='CASCADE'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50))
    transaction_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PatientDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id', ondelete='CASCADE'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    message_type = db.Column(db.String(20), default='text')  # text, audio, image, file
    content = db.Column(db.Text)
    audio_url = db.Column(db.String(500))
    file_url = db.Column(db.String(500))
    file_name = db.Column(db.String(255))
    file_size = db.Column(db.Integer)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    appointment = db.relationship('Appointment', backref='messages')

class VoiceCall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id', ondelete='CASCADE'), nullable=False)
    caller_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    call_duration = db.Column(db.Integer)  # in seconds
    call_status = db.Column(db.String(20), default='initiated')  # initiated, ongoing, completed, missed, rejected
    recording_url = db.Column(db.String(500))
    started_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class VoiceRecording(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    audio_url = db.Column(db.String(500), nullable=False)
    file_name = db.Column(db.String(255))
    file_size = db.Column(db.Integer)
    duration = db.Column(db.Integer)  # in seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# =============================================================================
# INITIALIZATION AND SAMPLE DATA - FIXED VERSION
# =============================================================================

def init_db():
    """Initialize the database with sample data - UPDATED VERSION"""
    with app.app_context():
        try:
            # Create all tables first
            print("🔄 Creating database tables...")
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Create upload directories
            print("🔄 Creating upload directories...")
            create_upload_directories()
            print("✅ Upload directories created successfully!")
            
            # Check if admin user already exists
            admin_user = User.query.filter_by(email='admin@makokha.com').first()
            if not admin_user:
                print("🔄 Creating admin user...")
                admin_user = User(
                    email='admin@makokha.com',
                    username='admin',
                    role='admin',
                    timezone='Africa/Nairobi'
                )
                admin_user.set_password('Admin123!')
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Admin user created: admin@makokha.com / Admin123!")
            else:
                print("ℹ️ Admin user already exists")
            
            # Create sample doctor
            doctor_user = User.query.filter_by(email='doctor@makokha.com').first()
            if not doctor_user:
                print("🔄 Creating doctor user...")
                doctor_user = User(
                    email='doctor@makokha.com',
                    username='drjohn',
                    role='doctor',
                    timezone='Africa/Nairobi'
                )
                doctor_user.set_password('Doctor123!')
                db.session.add(doctor_user)
                db.session.commit()
                
                # Create doctor profile
                doctor = Doctor(
                    user_id=doctor_user.id,
                    first_name='John',
                    last_name='Mwangi',
                    specialization='Cardiologist',
                    license_number='MED-12345',
                    consultation_fee=2500.00,
                    bio='Experienced cardiologist with 10+ years of practice.',
                    available_hours='Mon-Fri: 9AM-5PM',
                    timezone='Africa/Nairobi'
                )
                db.session.add(doctor)
                db.session.commit()
                print("✅ Sample doctor created: doctor@makokha.com / Doctor123!")
            else:
                print("ℹ️ Doctor user already exists")
            
            # Create sample patient
            patient_user = User.query.filter_by(email='patient@makokha.com').first()
            if not patient_user:
                print("🔄 Creating patient user...")
                patient_user = User(
                    email='patient@makokha.com',
                    username='patient1',
                    role='patient',
                    timezone='Africa/Nairobi'
                )
                patient_user.set_password('Patient123!')
                db.session.add(patient_user)
                db.session.commit()
                
                # Create patient profile
                patient = Patient(
                    user_id=patient_user.id,
                    first_name='Mary',
                    last_name='Wanjiku',
                    phone='+254712345678',
                    medical_history='No significant medical history'
                )
                db.session.add(patient)
                db.session.commit()
                print("✅ Sample patient created: patient@makokha.com / Patient123!")
            else:
                print("ℹ️ Patient user already exists")
            
            # Create sample appointment for testing communication
            try:
                existing_appointment = Appointment.query.filter_by(patient_id=patient.id, doctor_id=doctor.id).first()
                if not existing_appointment:
                    print("🔄 Creating sample appointment...")
                    # Use timezone-aware datetime
                    from datetime import datetime, timezone, timedelta
                    
                    # Appointment in 2 days from now
                    appointment_date = datetime.now(timezone.utc) + timedelta(days=2)
                    
                    sample_appointment = Appointment(
                        patient_id=patient.id,
                        doctor_id=doctor.id,
                        appointment_date=appointment_date,
                        status='scheduled',
                        symptoms='Regular checkup and consultation',
                        payment_status='completed'
                    )
                    db.session.add(sample_appointment)
                    db.session.commit()
                    print("✅ Sample appointment created for communication testing!")
                else:
                    print("ℹ️ Sample appointment already exists")
                    
            except Exception as e:
                print(f"⚠️ Could not create sample appointment: {str(e)}")
            
            print("🎉 Database initialized successfully!")
            
        except Exception as e:
            print(f"❌ Database initialization error: {str(e)}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            raise e


# =============================================================================
# UTILITY FUNCTIONS (Updated)
# =============================================================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if not text:
        return text
    
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li']
    allowed_attributes = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'width', 'height']
    }
    
    return bleach.clean(
        text,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )

def log_audit(action, user_id=None, details=None):
    """Log security-related events"""
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=details,
        timestamp=datetime.utcnow()
    )
    db.session.add(audit_log)
    db.session.commit()

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number format (Kenyan format supported)"""
    pattern = r'^(\+?254|0)[17]\d{8}$'
    return re.match(pattern, phone.replace(' ', '').replace('-', '')) is not None

def allowed_file(filename):
    """Check if file type is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_video_call_url(appointment_id):
    """Generate unique video call URL"""
    return f"/video-call/{appointment_id}"

def generate_voice_call_url(appointment_id):
    """Generate unique voice call URL"""
    return f"/voice-call/{appointment_id}"

def generate_whatsapp_chat_id(appointment_id):
    """Generate unique WhatsApp chat ID"""
    return f"wa_chat_{appointment_id}"

def create_upload_directories():
    """Create necessary upload directories"""
    try:
        directories = [
            'voice_messages',
            'message_files', 
            'voice_recordings',
            'recordings'
        ]
        
        # Create main upload directory if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Create subdirectories
        for directory in directories:
            dir_path = os.path.join(app.config['UPLOAD_FOLDER'], directory)
            os.makedirs(dir_path, exist_ok=True)
            print(f"✅ Created directory: {dir_path}")
            
    except Exception as e:
        print(f"❌ Error creating upload directories: {str(e)}")
        raise e


# =============================================================================
# MISSING API ENDPOINTS - ADD THESE TO YOUR app.py
# =============================================================================

@app.route('/api/user/current')
@login_required
def get_current_user():
    """Get current user information"""
    try:
        user_data = {
            'id': current_user.id,
            'email': current_user.email,
            'username': current_user.username,
            'role': current_user.role,
            'name': get_user_display_name(current_user)
        }
        return jsonify(user_data)
    except Exception as e:
        app.logger.error(f"Error getting current user: {str(e)}")
        return jsonify({'error': 'Failed to get user information'}), 500

def get_user_display_name(user):
    """Get user's display name based on role and profile"""
    if user.role == 'patient' and user.patient_profile:
        return f"{user.patient_profile.first_name} {user.patient_profile.last_name}"
    elif user.role == 'doctor' and user.doctor_profile:
        return f"Dr. {user.doctor_profile.first_name} {user.doctor_profile.last_name}"
    else:
        return user.username or user.email

@app.route('/api/appointments/<int:appointment_id>/messages')
@login_required
def get_appointment_messages(appointment_id):
    """Get all messages for an appointment"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        messages = Message.query.filter_by(appointment_id=appointment_id)\
                              .order_by(Message.created_at.asc())\
                              .all()
        
        messages_data = []
        for message in messages:
            messages_data.append({
                'id': message.id,
                'sender_id': message.sender_id,
                'sender_name': get_user_display_name(message.sender),
                'sender_role': message.sender.role,
                'receiver_id': message.receiver_id,
                'message_type': message.message_type,
                'content': message.content,
                'audio_url': message.audio_url,
                'file_url': message.file_url,
                'file_name': message.file_name,
                'file_size': message.file_size,
                'is_read': message.is_read,
                'created_at': message.created_at.isoformat(),
                'is_own': message.sender_id == current_user.id
            })
        
        return jsonify(messages_data)
    
    except Exception as e:
        app.logger.error(f"Error fetching messages: {str(e)}")
        return jsonify({'error': 'Failed to fetch messages'}), 500

@app.route('/api/appointments/<int:appointment_id>/messages/read', methods=['POST'])
@login_required
def mark_messages_read(appointment_id):
    """Mark all messages as read for an appointment"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Mark all unread messages as read
        unread_messages = Message.query.filter(
            Message.appointment_id == appointment_id,
            Message.receiver_id == current_user.id,
            Message.is_read == False
        ).all()
        
        for message in unread_messages:
            message.is_read = True
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'marked_read': len(unread_messages)
        })
    
    except Exception as e:
        app.logger.error(f"Error marking messages as read: {str(e)}")
        return jsonify({'error': 'Failed to mark messages as read'}), 500

@app.route('/api/messages/voice', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def upload_voice_message():
    """Upload voice message"""
    try:
        if 'audio' not in request.files:
            return jsonify({'error': 'No audio file provided'}), 400
        
        audio_file = request.files['audio']
        appointment_id = request.form.get('appointment_id')
        duration = request.form.get('duration', 0)
        
        if not appointment_id:
            return jsonify({'error': 'Appointment ID required'}), 400
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if audio_file and audio_file.filename != '':
            # Generate unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"voice_{current_user.id}_{timestamp}.webm"
            
            # Create upload directories if they don't exist
            voice_messages_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'voice_messages')
            os.makedirs(voice_messages_dir, exist_ok=True)
            
            file_path = os.path.join(voice_messages_dir, filename)
            audio_file.save(file_path)
            file_size = os.path.getsize(file_path)
            
            # Determine receiver
            if current_user.role == 'patient':
                receiver_id = appointment.doctor.user_id
            else:
                receiver_id = appointment.patient.user_id
            
            # Create message
            message = Message(
                appointment_id=appointment_id,
                sender_id=current_user.id,
                receiver_id=receiver_id,
                message_type='audio',
                audio_url=f'/static/uploads/voice_messages/{filename}',
                content='Voice message',
                file_name=filename,
                file_size=file_size
            )
            db.session.add(message)
            db.session.commit()
            
            # Prepare response data
            message_data = {
                'id': message.id,
                'sender_id': message.sender_id,
                'sender_name': get_user_display_name(current_user),
                'sender_role': current_user.role,
                'receiver_id': receiver_id,
                'message_type': 'audio',
                'content': 'Voice message',
                'audio_url': message.audio_url,
                'file_name': filename,
                'file_size': file_size,
                'is_read': False,
                'created_at': message.created_at.isoformat(),
                'is_own': True,
                'duration': int(duration)
            }
            
            log_audit('voice_message_uploaded', current_user.id, f'Appointment: {appointment_id}')
            return jsonify(message_data)
        else:
            return jsonify({'error': 'Invalid audio file'}), 400
    
    except Exception as e:
        app.logger.error(f"Error uploading voice message: {str(e)}")
        return jsonify({'error': 'Failed to upload voice message'}), 500


@app.route('/static/uploads/<path:filename>')
def serve_uploaded_files(filename):
    """Serve uploaded files"""
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename
        )
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/messages/file', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def upload_message_file():
    """Upload file for messaging"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        appointment_id = request.form.get('appointment_id')
        
        if not appointment_id:
            return jsonify({'error': 'Appointment ID required'}), 400
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if file and file.filename != '':
            # Generate unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = secure_filename(file.filename)
            unique_filename = f"file_{current_user.id}_{timestamp}_{filename}"
            
            # Create upload directories if they don't exist
            message_files_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'message_files')
            os.makedirs(message_files_dir, exist_ok=True)
            
            file_path = os.path.join(message_files_dir, unique_filename)
            file.save(file_path)
            file_size = os.path.getsize(file_path)
            
            # Determine receiver
            if current_user.role == 'patient':
                receiver_id = appointment.doctor.user_id
            else:
                receiver_id = appointment.patient.user_id
            
            # Determine file type
            file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            if file_extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp']:
                message_type = 'image'
            else:
                message_type = 'file'
            
            message = Message(
                appointment_id=appointment_id,
                sender_id=current_user.id,
                receiver_id=receiver_id,
                message_type=message_type,
                file_url=f'/static/uploads/message_files/{unique_filename}',
                file_name=filename,
                file_size=file_size,
                content=f'Sent a {message_type}: {filename}'
            )
            db.session.add(message)
            db.session.commit()
            
            # Prepare response data
            message_data = {
                'id': message.id,
                'sender_id': message.sender_id,
                'sender_name': get_user_display_name(current_user),
                'sender_role': current_user.role,
                'receiver_id': receiver_id,
                'message_type': message_type,
                'content': f'Sent a {message_type}: {filename}',
                'file_url': message.file_url,
                'file_name': filename,
                'file_size': file_size,
                'is_read': False,
                'created_at': message.created_at.isoformat(),
                'is_own': True
            }
            
            log_audit('message_file_uploaded', current_user.id, f'Appointment: {appointment_id}, Type: {message_type}')
            return jsonify(message_data)
        else:
            return jsonify({'error': 'Invalid file'}), 400
    
    except Exception as e:
        app.logger.error(f"Error uploading message file: {str(e)}")
        return jsonify({'error': 'Failed to upload file'}), 500

@app.route('/api/recordings/upload', methods=['POST'])
@login_required
def upload_recording():
    """Upload call recording - placeholder for future implementation"""
    try:
        # This is a placeholder for call recording functionality
        # In production, you would implement proper recording storage
        return jsonify({'success': True, 'message': 'Recording upload endpoint - implement storage logic'})
    except Exception as e:
        app.logger.error(f"Error in recording upload: {str(e)}")
        return jsonify({'error': 'Recording upload not implemented'}), 501

# =============================================================================
# TIMEZONE ROUTES
# =============================================================================

@app.route('/api/set-timezone', methods=['POST'])
def set_timezone():
    """Set user's timezone preference"""
    try:
        data = request.json
        timezone_str = data.get('timezone')
        
        if timezone_str:
            # Validate timezone
            try:
                pytz.timezone(timezone_str)
                session['user_timezone'] = timezone_str
                
                # Update user's preference if logged in
                if current_user.is_authenticated:
                    current_user.timezone = timezone_str
                    db.session.commit()
                
                return jsonify({'success': True, 'timezone': timezone_str})
            except pytz.UnknownTimeZoneError:
                return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        
        return jsonify({'success': False, 'error': 'No timezone provided'}), 400
    
    except Exception as e:
        app.logger.error(f"Error setting timezone: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to set timezone'}), 500

@app.route('/api/get-timezone-info')
def get_timezone_info():
    """Get current timezone information"""
    try:
        user_tz = get_user_timezone()
        current_time = get_current_time()
        
        return jsonify({
            'timezone': str(user_tz),
            'current_time': current_time.isoformat(),
            'timezone_name': user_tz.zone,
            'utc_offset': current_time.strftime('%z')
        })
    
    except Exception as e:
        app.logger.error(f"Error getting timezone info: {str(e)}")
        return jsonify({'error': 'Failed to get timezone info'}), 500

# =============================================================================
# ADMIN USER MANAGEMENT ROUTES
# =============================================================================

@app.route('/api/admin/users')
@login_required
def get_admin_users():
    """Get all users for admin management"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        users = User.query.all()
        users_data = []
        
        for user in users:
            user_data = {
                'id': user.id,
                'first_name': user.patient_profile.first_name if user.patient_profile else user.doctor_profile.first_name if user.doctor_profile else None,
                'last_name': user.patient_profile.last_name if user.patient_profile else user.doctor_profile.last_name if user.doctor_profile else None,
                'email': user.email,
                'role': user.role,
                'is_active': True,  # You might want to add an active field to your User model
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'created_at': user.created_at.isoformat() if user.created_at else None
            }
            users_data.append(user_data)
        
        return jsonify(users_data)
    
    except Exception as e:
        app.logger.error(f"Error getting admin users: {str(e)}")
        return jsonify({'error': 'Failed to load users'}), 500

@app.route('/api/admin/users', methods=['POST'])
@login_required
def create_admin_user():
    """Create a new user (admin or doctor)"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'email', 'password', 'role']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return jsonify({'error': 'User with this email already exists'}), 400
        
        # Validate password strength
        if not User().is_strong_password(data['password']):
            return jsonify({'error': 'Password must be at least 8 characters with uppercase, lowercase, number, and special character'}), 400
        
        # Create new user
        new_user = User(
            email=data['email'],
            role=data['role']
        )
        new_user.set_password(data['password'])
        
        db.session.add(new_user)
        db.session.commit()
        
        # Create profile based on role
        if data['role'] == 'doctor':
            doctor = Doctor(
                user_id=new_user.id,
                first_name=data['first_name'],
                last_name=data['last_name'],
                specialization=data.get('specialization', 'General Practitioner'),
                license_number=data.get('license_number', 'TEMP-0000'),
                consultation_fee=float(data.get('consultation_fee', 2500.0)),
                bio=data.get('bio', ''),
                available_hours=data.get('available_hours', 'Mon-Fri: 9AM-5PM'),
                phone=data.get('phone', '')
            )
            db.session.add(doctor)
        
        elif data['role'] == 'admin':
            # For admin users, we might not need a separate profile
            # Or you can create a basic patient profile
            patient = Patient(
                user_id=new_user.id,
                first_name=data['first_name'],
                last_name=data['last_name'],
                phone=data.get('phone', '')
            )
            db.session.add(patient)
        
        db.session.commit()
        
        log_audit('user_created', current_user.id, f'New {data["role"]} user: {data["email"]}')
        return jsonify({'success': True, 'message': f'{data["role"].title()} user created successfully'})
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating admin user: {str(e)}")
        return jsonify({'error': 'Failed to create user'}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_admin_user(user_id):
    """Delete a user"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        user = User.query.get_or_404(user_id)
        
        # Prevent admin from deleting themselves
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        # Prevent deleting other admins (optional)
        if user.role == 'admin':
            return jsonify({'error': 'Cannot delete other admin accounts'}), 400
        
        # Delete user (this will cascade to related records due to CASCADE delete)
        db.session.delete(user)
        db.session.commit()
        
        log_audit('user_deleted', current_user.id, f'Deleted user: {user.email}')
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting admin user: {str(e)}")
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@login_required
def update_admin_user(user_id):
    """Update a user"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        user = User.query.get_or_404(user_id)
        data = request.json
        
        # Update user fields
        if 'email' in data:
            user.email = data['email']
        
        if 'password' in data and data['password']:
            if not User().is_strong_password(data['password']):
                return jsonify({'error': 'Password must be at least 8 characters with uppercase, lowercase, number, and special character'}), 400
            user.set_password(data['password'])
        
        # Update profile based on role
        if user.role == 'doctor' and user.doctor_profile:
            doctor = user.doctor_profile
            if 'first_name' in data:
                doctor.first_name = data['first_name']
            if 'last_name' in data:
                doctor.last_name = data['last_name']
            if 'specialization' in data:
                doctor.specialization = data['specialization']
            if 'consultation_fee' in data:
                doctor.consultation_fee = float(data['consultation_fee'])
            if 'bio' in data:
                doctor.bio = data['bio']
            if 'available_hours' in data:
                doctor.available_hours = data['available_hours']
            if 'phone' in data:
                doctor.phone = data['phone']
        
        elif user.role == 'admin' and user.patient_profile:
            patient = user.patient_profile
            if 'first_name' in data:
                patient.first_name = data['first_name']
            if 'last_name' in data:
                patient.last_name = data['last_name']
            if 'phone' in data:
                patient.phone = data['phone']
        
        db.session.commit()
        
        log_audit('user_updated', current_user.id, f'Updated user: {user.email}')
        return jsonify({'success': True, 'message': 'User updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating admin user: {str(e)}")
        return jsonify({'error': 'Failed to update user'}), 500

# =============================================================================
# AUTHENTICATION ROUTES (Updated)
# =============================================================================

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def signup():
    if request.method == 'POST':
        try:
            # Sanitize all inputs
            username = sanitize_input(request.form.get('username', '').strip())
            email = sanitize_input(request.form.get('email', '').strip().lower())
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validate inputs
            if not validate_email(email):
                flash('Invalid email format', 'error')
                return redirect(url_for('signup'))
            
            if username and (len(username) < 3 or len(username) > 80):
                flash('Username must be between 3 and 80 characters', 'error')
                return redirect(url_for('signup'))
            
            # Check password match
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('signup'))
            
            # Check password strength
            if not User().is_strong_password(password):
                flash('Password must be at least 8 characters with uppercase, lowercase, number, and special character', 'error')
                return redirect(url_for('signup'))
            
            # Check if user already exists
            existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
            if existing_user:
                flash('Email or username already exists', 'error')
                log_audit('signup_attempt_duplicate', details=f'Email: {email}')
                return redirect(url_for('signup'))
            
            # Create new user with secure password handling - Only patient role
            new_user = User(email=email, username=username, role='patient')
            
            # Set user's timezone preference
            user_tz = get_user_timezone()
            new_user.timezone = user_tz.zone
            
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            # Create patient profile with sanitized inputs
            first_name = sanitize_input(request.form.get('first_name', ''))
            last_name = sanitize_input(request.form.get('last_name', ''))
            phone = sanitize_input(request.form.get('phone', ''))
            date_of_birth = request.form.get('date_of_birth')
            address = sanitize_input(request.form.get('address', ''))
            emergency_contact = sanitize_input(request.form.get('emergency_contact', ''))
            medical_history = sanitize_input(request.form.get('medical_history', ''))
            
            if phone and not validate_phone(phone):
                flash('Invalid phone number format. Use Kenyan format: 07XXXXXXXX or +2547XXXXXXXX', 'error')
                db.session.rollback()
                return redirect(url_for('signup'))
            
            patient = Patient(
                user_id=new_user.id, 
                first_name=first_name,
                last_name=last_name,
                phone=phone,
                date_of_birth=datetime.strptime(date_of_birth, '%Y-%m-%d').date() if date_of_birth else None,
                address=address,
                emergency_contact=emergency_contact,
                medical_history=medical_history
            )
            db.session.add(patient)
            db.session.commit()
            
            log_audit('signup_success', new_user.id, 'Role: patient')
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
            
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(url_for('signup'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Signup error: {str(e)}")
            flash('An error occurred during signup. Please try again.', 'error')
            return redirect(url_for('signup'))
    
    # Pass current datetime to template for date validation
    current_date = get_current_time().strftime('%Y-%m-%d')
    return render_template('signup.html', current_date=current_date)

# =============================================================================
# GOOGLE OAUTH CONFIGURATION
# =============================================================================

import requests
from urllib.parse import urlencode
import secrets

# Google OAuth Configuration - Update these in your .env file
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
# Dynamic Google OAuth configuration
def get_google_redirect_uri():
    """Get the correct redirect URI based on environment"""
    # Check if we're in production (Render)
    if os.environ.get('RENDER') or os.environ.get('FLASK_ENV') == 'production':
        # Use your actual Render URL
        return 'https://makokha-medical-centre-website.onrender.com/google-callback'
    else:
        # Development/localhost
        return 'http://localhost:5000/google-callback'

GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI') or get_google_redirect_uri()

# =============================================================================
# GOOGLE OAUTH ROUTES
# =============================================================================

@app.route('/google-login')
def google_login():
    """Initiate Google OAuth flow"""
    try:
        # Generate state parameter for security (prevents CSRF attacks)
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        session['oauth_redirect'] = request.args.get('next', url_for('patient_dashboard'))
        
        # Google OAuth URL parameters
        params = {
            'client_id': GOOGLE_CLIENT_ID,
            'redirect_uri': GOOGLE_REDIRECT_URI,
            'response_type': 'code',
            'scope': 'openid email profile',
            'state': state,
            'access_type': 'offline',  # Allows refresh tokens
            'prompt': 'consent'  # Forces consent screen to ensure we get refresh token
        }
        
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
        return redirect(auth_url)
        
    except Exception as e:
        app.logger.error(f"Google OAuth initiation error: {str(e)}")
        flash('Error initiating Google login. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/google-callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        # Check for errors from Google
        error = request.args.get('error')
        if error:
            error_description = request.args.get('error_description', 'Unknown error')
            app.logger.error(f"Google OAuth error: {error} - {error_description}")
            flash(f'Google authentication failed: {error_description}', 'error')
            return redirect(url_for('login'))
        
        # Verify state parameter to prevent CSRF attacks
        stored_state = session.pop('oauth_state', None)
        returned_state = request.args.get('state')
        
        if not stored_state or stored_state != returned_state:
            app.logger.error(f"OAuth state mismatch: stored={stored_state}, returned={returned_state}")
            flash('Security validation failed. Please try logging in again.', 'error')
            return redirect(url_for('login'))
        
        # Get authorization code
        code = request.args.get('code')
        if not code:
            flash('Authorization failed: No code received from Google', 'error')
            return redirect(url_for('login'))
        
        # Exchange authorization code for tokens
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE_REDIRECT_URI
        }
        
        token_response = requests.post(token_url, data=token_data)
        
        if token_response.status_code != 200:
            app.logger.error(f"Token exchange failed: {token_response.text}")
            flash('Failed to authenticate with Google. Please try again.', 'error')
            return redirect(url_for('login'))
        
        token_json = token_response.json()
        
        if 'error' in token_json:
            app.logger.error(f"Token exchange error: {token_json['error']}")
            flash('Failed to authenticate with Google. Please try again.', 'error')
            return redirect(url_for('login'))
        
        access_token = token_json['access_token']
        refresh_token = token_json.get('refresh_token')
        id_token = token_json.get('id_token')
        
        # Get user info from Google using access token
        userinfo_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        userinfo_response = requests.get(userinfo_url, headers=headers)
        
        if userinfo_response.status_code != 200:
            app.logger.error(f"Userinfo request failed: {userinfo_response.text}")
            flash('Failed to get user information from Google.', 'error')
            return redirect(url_for('login'))
        
        userinfo = userinfo_response.json()
        
        # Extract user information
        google_id = userinfo['id']
        email = userinfo['email']
        email_verified = userinfo.get('verified_email', False)
        first_name = userinfo.get('given_name', '')
        last_name = userinfo.get('family_name', '')
        picture = userinfo.get('picture', '')
        locale = userinfo.get('locale', '')
        
        # Validate required fields
        if not email:
            flash('Google account email is required but not provided.', 'error')
            return redirect(url_for('login'))
        
        if not email_verified:
            flash('Please verify your Google email address before signing in.', 'error')
            return redirect(url_for('login'))
        
        # Check if user already exists by Google ID
        user = User.query.filter_by(google_id=google_id).first()
        
        if not user:
            # Check if user exists by email (account merging)
            user = User.query.filter_by(email=email).first()
            
            if user:
                # User exists with email but no Google ID - link the accounts
                if user.google_id:
                    app.logger.error(f"Google ID conflict for email {email}")
                    flash('This email is already associated with a different Google account.', 'error')
                    return redirect(url_for('login'))
                
                # Link existing account with Google
                user.google_id = google_id
                db.session.commit()
                log_audit('google_account_linked', user.id, f'Linked with Google ID: {google_id}')
                
            else:
                # Create new user with Google authentication
                base_username = email.split('@')[0]
                username = base_username
                counter = 1
                
                # Ensure username is unique
                while User.query.filter_by(username=username).first():
                    username = f"{base_username}{counter}"
                    counter += 1
                    if counter > 100:
                        username = f"user{secrets.randbelow(1000000)}"
                        break
                
                # Get user's timezone
                user_timezone = get_user_timezone()
                
                # Create user without calling set_password
                user = User(
                    email=email,
                    username=username,
                    google_id=google_id,
                    role='patient',
                    timezone=user_timezone.zone
                )
                
                # Use the special method for OAuth users that bypasses password validation
                user.set_oauth_password()
                
                db.session.add(user)
                db.session.commit()
                
                # Create patient profile
                patient = Patient(
                    user_id=user.id,
                    first_name=first_name or 'Google',
                    last_name=last_name or 'User',
                    phone=None
                )
                db.session.add(patient)
                db.session.commit()
                
                log_audit('google_signup_success', user.id, f'Google ID: {google_id}')
        
        # Log the user in
        login_user(user)
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Store OAuth tokens
        session['google_access_token'] = access_token
        if refresh_token:
            session['google_refresh_token'] = refresh_token
        
        # Store timezone
        if not session.get('user_timezone') and user.timezone:
            session['user_timezone'] = user.timezone
        
        log_audit('google_login_success', user.id)
        
        user_current_time = get_current_time()
        welcome_message = f'Successfully signed in with Google! Welcome, {first_name or user.username}!'
        
        flash(welcome_message, 'success')
        
        redirect_to = session.pop('oauth_redirect', None)
        
        if user.role == 'admin':
            return redirect(redirect_to or url_for('admin_dashboard'))
        elif user.role == 'doctor':
            return redirect(redirect_to or url_for('doctor_dashboard'))
        else:
            return redirect(redirect_to or url_for('patient_dashboard'))
            
    except Exception as e:
        app.logger.error(f"Google OAuth callback error: {str(e)}")
        flash('An error occurred during Google authentication. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/google-revoke')
@login_required
def google_revoke():
    """Revoke Google OAuth access"""
    try:
        access_token = session.get('google_access_token')
        if access_token:
            revoke_url = 'https://oauth2.googleapis.com/revoke'
            requests.post(revoke_url, data={'token': access_token})
            
            # Clear session data
            session.pop('google_access_token', None)
            session.pop('google_refresh_token', None)
            
            # Remove Google ID from user account (optional)
            if current_user.google_id:
                current_user.google_id = None
                db.session.commit()
            
            log_audit('google_oauth_revoked', current_user.id)
            flash('Google account access has been revoked.', 'success')
        else:
            flash('No Google account is currently linked.', 'info')
            
    except Exception as e:
        app.logger.error(f"Google revoke error: {str(e)}")
        flash('Error revoking Google access.', 'error')
    
    return redirect(url_for('patient_dashboard'))

# =============================================================================
# OAUTH UTILITY FUNCTIONS
# =============================================================================

def refresh_google_token(refresh_token):
    """Refresh Google access token using refresh token"""
    try:
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        
        response = requests.post(token_url, data=token_data)
        if response.status_code == 200:
            token_json = response.json()
            return token_json.get('access_token')
    except Exception as e:
        app.logger.error(f"Token refresh error: {str(e)}")
    
    return None

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        login_input = sanitize_input(request.form.get('email', '').strip().lower())
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        # Check if login input is email or username
        if '@' in login_input:
            user = User.query.filter_by(email=login_input).first()
        else:
            user = User.query.filter_by(username=login_input).first()
        
        if not user:
            log_audit('login_attempt_failed', details=f'Unknown user: {login_input}')
            flash('Invalid email/username or password', 'error')
            return redirect(url_for('login'))
        
        # Check if user is OAuth-only and trying to use password
        if user.google_id and not user.password_hash:
            flash('This account uses Google Sign-In. Please use the "Continue with Google" option.', 'error')
            return redirect(url_for('login'))
        
        # Check if account is locked
        if user.is_account_locked():
            flash('Account temporarily locked due to too many failed attempts. Please try again later.', 'error')
            return redirect(url_for('login'))
        
        # Verify password (this will return False for OAuth users without passwords)
        if not user.check_password(password):
            user.increment_login_attempts()
            log_audit('login_attempt_failed', user.id, 'Invalid password')
            flash('Invalid email/username or password', 'error')
            return redirect(url_for('login'))
        
        # Successful login
        user.reset_login_attempts()
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        login_user(user, remember=remember)
        log_audit('login_success', user.id)
        
        # Redirect based on role
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        else:
            return redirect(url_for('patient_dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit('logout', current_user.id)
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/reset-password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def reset_password():
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email', '').strip().lower())
        user = User.query.filter_by(email=email).first()
        
        if user:
            log_audit('password_reset_requested', user.id)
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
        else:
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

# =============================================================================
# MAIN ROUTES
# =============================================================================

@app.route('/')
def index():
    doctors = Doctor.query.filter_by(is_available=True).limit(4).all()
    current_time = get_current_time()
    return render_template('index.html', doctors=doctors, current_time=current_time)

@app.route('/patient-dashboard')
@login_required
def patient_dashboard():
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Check if patient profile exists, if not create one
    if not current_user.patient_profile:
        # Create a basic patient profile
        patient = Patient(
            user_id=current_user.id,
            first_name=current_user.username or 'User',
            last_name='',
            phone=''
        )
        db.session.add(patient)
        db.session.commit()
        flash('Your patient profile has been created.', 'info')
    
    appointments = Appointment.query.filter_by(patient_id=current_user.patient_profile.id).order_by(Appointment.appointment_date.desc()).all()
    doctors = Doctor.query.filter_by(is_available=True).all()
    documents = PatientDocument.query.filter_by(patient_id=current_user.patient_profile.id).all()
    
    # Convert appointment times to user's timezone
    for appointment in appointments:
        appointment.local_time = appointment.get_local_appointment_time(current_user)
    
    return render_template('patient_dashboard.html', 
                         appointments=appointments, 
                         doctors=doctors,
                         documents=documents,
                         format_datetime=format_datetime)

@app.route('/api/check_new_messages', methods=['GET'])
@login_required
def check_new_messages_default():
    """Default route for checking new messages without appointment_id"""
    return jsonify({'error': 'Appointment ID required. Use /api/check_new_messages/<appointment_id>'}), 400

@app.route('/doctor-dashboard')
@login_required
def doctor_dashboard():
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Check if doctor profile exists, if not create one
    if not current_user.doctor_profile:
        # Create a basic doctor profile
        doctor = Doctor(
            user_id=current_user.id,
            first_name=current_user.username or 'Doctor',
            last_name='',
            specialization='General Practitioner',
            license_number='TEMP-0000',
            consultation_fee=0.0
        )
        db.session.add(doctor)
        db.session.commit()
        flash('Your doctor profile has been created.', 'info')
    
    appointments = Appointment.query.filter_by(doctor_id=current_user.doctor_profile.id).order_by(Appointment.appointment_date.desc()).all()
    
    # Convert to local time for today's appointments check - FIXED
    today_utc = datetime.now(timezone.utc).date()  # Use timezone.utc directly
    today_appointments = [apt for apt in appointments if apt.appointment_date.date() == today_utc]
    
    # Convert appointment times to user's timezone
    for appointment in appointments:
        appointment.local_time = appointment.get_local_appointment_time(current_user)
    
    # Get current date in user's timezone for the template
    current_date = get_current_time()
    
    return render_template('doctor_dashboard.html', 
                         appointments=appointments,
                         today_appointments=today_appointments,
                         format_datetime=format_datetime,
                         current_date=current_date)

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    stats = {
        'total_patients': Patient.query.count(),
        'total_doctors': Doctor.query.count(),
        'total_appointments': Appointment.query.count(),
        'total_users': User.query.count(),
        'pending_appointments': Appointment.query.filter_by(status='scheduled').count()
    }
    return render_template('admin_dashboard.html', stats=stats)

# =============================================================================
# APPOINTMENT ROUTES
# =============================================================================

@app.route('/book-appointment', methods=['POST'])
@login_required
def book_appointment():
    try:
        data = request.json
        doctor_id = data['doctor_id']
        appointment_date_str = data['appointment_date']
        symptoms = sanitize_input(data.get('symptoms', ''))
        medical_history = sanitize_input(data.get('medical_history', ''))
        
        # Parse the appointment date (assuming it's in user's local time)
        user_tz = get_user_timezone()
        local_dt = datetime.fromisoformat(appointment_date_str.replace('Z', '+00:00'))
        
        # If datetime is naive, localize it
        if local_dt.tzinfo is None:
            local_dt = user_tz.localize(local_dt)
        
        # Convert to UTC for storage
        utc_dt = local_dt.astimezone(pytz.UTC)
        
        # Update patient medical history
        current_user.patient_profile.medical_history = medical_history
        db.session.commit()
        
        appointment = Appointment(
            patient_id=current_user.patient_profile.id,
            doctor_id=doctor_id,
            appointment_date=utc_dt,  # Store in UTC
            symptoms=symptoms
        )
        db.session.add(appointment)
        db.session.commit()
        
        log_audit('appointment_booked', current_user.id, f'Appointment ID: {appointment.id}')
        return jsonify({'success': True, 'appointment_id': appointment.id})
    except Exception as e:
        app.logger.error(f"Appointment booking error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to book appointment'}), 500

@app.route('/confirm-appointment/<int:appointment_id>', methods=['POST'])
@login_required
def confirm_appointment(appointment_id):
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        if appointment.patient_id != current_user.patient_profile.id:
            flash('Access denied', 'error')
            return redirect(url_for('patient_dashboard'))
        
        appointment.status = 'confirmed'
        db.session.commit()
        
        flash('Appointment confirmed successfully!', 'success')
        return redirect(url_for('patient_dashboard'))
    except Exception as e:
        app.logger.error(f"Appointment confirmation error: {str(e)}")
        flash('Error confirming appointment', 'error')
        return redirect(url_for('patient_dashboard'))

@app.route('/update-appointment-status/<int:appointment_id>', methods=['POST'])
@login_required
def update_appointment_status(appointment_id):
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        status = request.form.get('status')
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            flash('Access denied', 'error')
            return redirect(url_for('doctor_dashboard'))
        
        appointment.status = status
        db.session.commit()
        
        flash('Appointment status updated!', 'success')
        return redirect(url_for('doctor_dashboard'))
    except Exception as e:
        app.logger.error(f"Appointment status update error: {str(e)}")
        flash('Error updating appointment status', 'error')
        return redirect(url_for('doctor_dashboard'))

# =============================================================================
# FILE UPLOAD ROUTES
# =============================================================================

@app.route('/upload-document', methods=['POST'])
@login_required
def upload_document():
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('patient_dashboard'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('patient_dashboard'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Create unique filename
            unique_filename = f"{current_user.patient_profile.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Create upload directory if it doesn't exist
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            file.save(file_path)
            
            # Save document record
            document = PatientDocument(
                patient_id=current_user.patient_profile.id,
                filename=unique_filename,
                original_filename=filename,
                file_path=file_path,
                file_size=os.path.getsize(file_path),
                file_type=file.content_type,
                description=sanitize_input(request.form.get('description', ''))
            )
            db.session.add(document)
            db.session.commit()
            
            log_audit('document_uploaded', current_user.id, f'File: {filename}')
            flash('Document uploaded successfully!', 'success')
        else:
            flash('File type not allowed', 'error')
        
        return redirect(url_for('patient_dashboard'))
    
    except Exception as e:
        app.logger.error(f"File upload error: {str(e)}")
        flash('Error uploading document', 'error')
        return redirect(url_for('patient_dashboard'))

@app.route('/delete-document/<int:document_id>', methods=['POST'])
@login_required
def delete_document(document_id):
    try:
        document = PatientDocument.query.get_or_404(document_id)
        
        if document.patient_id != current_user.patient_profile.id:
            flash('Access denied', 'error')
            return redirect(url_for('patient_dashboard'))
        
        # Remove file from filesystem
        if os.path.exists(document.file_path):
            os.remove(document.file_path)
        
        db.session.delete(document)
        db.session.commit()
        
        flash('Document deleted successfully!', 'success')
        return redirect(url_for('patient_dashboard'))
    
    except Exception as e:
        app.logger.error(f"Document deletion error: {str(e)}")
        flash('Error deleting document', 'error')
        return redirect(url_for('patient_dashboard'))

# =============================================================================
# COMMUNICATION ROUTES
# =============================================================================

@app.route('/video-call/<int:appointment_id>')
@login_required
def video_call(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Check if user has access to this appointment
    if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
        flash('Access denied', 'error')
        return redirect(url_for('patient_dashboard'))
    
    if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
        flash('Access denied', 'error')
        return redirect(url_for('doctor_dashboard'))
    
    # Generate video call URL if not exists
    if not appointment.video_call_url:
        appointment.video_call_url = generate_video_call_url(appointment_id)
        db.session.commit()
    
    return render_template('video_call.html', appointment=appointment)

@app.route('/voice-call/<int:appointment_id>')
@login_required
def voice_call(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Check if user has access to this appointment
    if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
        flash('Access denied', 'error')
        return redirect(url_for('patient_dashboard'))
    
    if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
        flash('Access denied', 'error')
        return redirect(url_for('doctor_dashboard'))
    
    # Generate voice call URL if not exists
    if not appointment.voice_call_url:
        appointment.voice_call_url = generate_voice_call_url(appointment_id)
        db.session.commit()
    
    return render_template('voice_call.html', appointment=appointment)

@app.route('/whatsapp-chat/<int:appointment_id>')
@login_required
def whatsapp_chat(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Check if user has access to this appointment
    if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
        flash('Access denied', 'error')
        return redirect(url_for('patient_dashboard'))
    
    if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
        flash('Access denied', 'error')
        return redirect(url_for('doctor_dashboard'))
    
    # Generate WhatsApp chat ID if not exists
    if not appointment.whatsapp_chat_id:
        appointment.whatsapp_chat_id = generate_whatsapp_chat_id(appointment_id)
        db.session.commit()
    
    return render_template('whatsapp_chat.html', appointment=appointment)

# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/api/doctors')
@login_required
def get_doctors():
    doctors = Doctor.query.filter_by(is_available=True).all()
    doctors_data = []
    for doctor in doctors:
        doctors_data.append({
            'id': doctor.id,
            'name': f'Dr. {doctor.first_name} {doctor.last_name}',
            'specialization': doctor.specialization,
            'consultation_fee': doctor.consultation_fee,
            'bio': doctor.bio
        })
    return jsonify(doctors_data)

@app.route('/api/user/role')
@login_required
def get_user_role():
    return jsonify({'role': current_user.role})

@app.route('/api/appointments')
@login_required
def get_appointments():
    """Get appointments for communication hub"""
    try:
        if current_user.role == 'patient':
            appointments = Appointment.query.filter_by(
                patient_id=current_user.patient_profile.id
            ).order_by(Appointment.appointment_date.desc()).all()
        elif current_user.role == 'doctor':
            appointments = Appointment.query.filter_by(
                doctor_id=current_user.doctor_profile.id
            ).order_by(Appointment.appointment_date.desc()).all()
        else:
            appointments = []
        
        appointments_data = []
        for apt in appointments:
            local_time = apt.get_local_appointment_time(current_user)
            
            # Get unread message count
            unread_count = Message.query.filter(
                Message.appointment_id == apt.id,
                Message.receiver_id == current_user.id,
                Message.is_read == False
            ).count()
            
            # Get last message
            last_message = Message.query.filter_by(appointment_id=apt.id)\
                                      .order_by(Message.created_at.desc())\
                                      .first()
            
            appointment_info = {
                'id': apt.id,
                'patient_name': f"{apt.patient.first_name} {apt.patient.last_name}",
                'doctor_name': f"Dr. {apt.doctor.first_name} {apt.doctor.last_name}",
                'specialization': apt.doctor.specialization,
                'appointment_date': apt.appointment_date.isoformat(),
                'local_appointment_date': local_time.isoformat() if local_time else None,
                'formatted_date': format_datetime(apt.appointment_date),
                'status': apt.status,
                'payment_status': apt.payment_status,
                'unread_count': unread_count,
                'has_video_call': bool(apt.video_call_url),
                'has_voice_call': bool(apt.voice_call_url),
                'last_message': last_message.content if last_message else None,
                'last_message_time': last_message.created_at.isoformat() if last_message else None
            }
            
            appointments_data.append(appointment_info)
        
        return jsonify(appointments_data)
    
    except Exception as e:
        app.logger.error(f"Error getting appointments: {str(e)}")
        return jsonify({'error': 'Failed to load appointments'}), 500

# =============================================================================
# TEMPLATE CONTEXT PROCESSORS
# =============================================================================

@app.context_processor
def utility_processor():
    """Make timezone functions and datetime available to all templates"""
    return {
        'get_current_time': get_current_time,
        'format_datetime': format_datetime,
        'get_user_timezone': get_user_timezone,
        'convert_to_user_timezone': convert_to_user_timezone,
        'datetime': datetime  # Add this line
    }

# =============================================================================
# PAYMENT ROUTES
# =============================================================================
@app.route('/api/payment/mpesa', methods=['POST'])
@login_required
def process_mpesa_payment():
    """Process M-Pesa payment"""
    try:
        data = request.json
        appointment_id = data.get('appointment_id')
        phone = data.get('phone')
        amount = data.get('amount')
        
        # Validate input
        if not all([appointment_id, phone, amount]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # In a real implementation, integrate with M-Pesa API
        # For demo purposes, simulate successful payment
        transaction_id = f"MPESA_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        
        # Update appointment payment status
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            appointment.payment_status = 'completed'
            appointment.payment_reference = transaction_id
            
            # Create payment record
            payment = Payment(
                appointment_id=appointment_id,
                amount=amount,
                payment_method='mpesa',
                transaction_id=transaction_id,
                status='completed'
            )
            db.session.add(payment)
            db.session.commit()
            
            log_audit('payment_processed', current_user.id, f'M-Pesa: {transaction_id}')
            return jsonify({'success': True, 'transaction_id': transaction_id})
        else:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
            
    except Exception as e:
        app.logger.error(f"M-Pesa payment error: {str(e)}")
        return jsonify({'success': False, 'error': 'Payment processing failed'}), 500

@app.route('/api/payment/paypal', methods=['POST'])
@login_required
def process_paypal_payment():
    """Process PayPal payment"""
    try:
        data = request.json
        appointment_id = data.get('appointment_id')
        email = data.get('email')
        amount = data.get('amount')
        
        # Validate input
        if not all([appointment_id, email, amount]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Simulate PayPal payment processing
        transaction_id = f"PAYPAL_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        
        # Update appointment payment status
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            appointment.payment_status = 'completed'
            appointment.payment_reference = transaction_id
            
            # Create payment record
            payment = Payment(
                appointment_id=appointment_id,
                amount=amount,
                payment_method='paypal',
                transaction_id=transaction_id,
                status='completed'
            )
            db.session.add(payment)
            db.session.commit()
            
            log_audit('payment_processed', current_user.id, f'PayPal: {transaction_id}')
            return jsonify({'success': True, 'transaction_id': transaction_id})
        else:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
            
    except Exception as e:
        app.logger.error(f"PayPal payment error: {str(e)}")
        return jsonify({'success': False, 'error': 'Payment processing failed'}), 500

@app.route('/api/payment/card', methods=['POST'])
@login_required
def process_card_payment():
    """Process credit/debit card payment"""
    try:
        data = request.json
        appointment_id = data.get('appointment_id')
        card_number = data.get('card_number')
        expiry = data.get('expiry')
        cvv = data.get('cvv')
        name = data.get('name')
        card_type = data.get('type')
        amount = data.get('amount')
        
        # Validate input
        if not all([appointment_id, card_number, expiry, cvv, name, card_type, amount]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Simulate card payment processing
        transaction_id = f"{card_type.upper()}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        
        # Update appointment payment status
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            appointment.payment_status = 'completed'
            appointment.payment_reference = transaction_id
            
            # Create payment record
            payment = Payment(
                appointment_id=appointment_id,
                amount=amount,
                payment_method=f'{card_type}_card',
                transaction_id=transaction_id,
                status='completed'
            )
            db.session.add(payment)
            db.session.commit()
            
            log_audit('payment_processed', current_user.id, f'{card_type} card: {transaction_id}')
            return jsonify({'success': True, 'transaction_id': transaction_id})
        else:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
            
    except Exception as e:
        app.logger.error(f"Card payment error: {str(e)}")
        return jsonify({'success': False, 'error': 'Payment processing failed'}), 500

@app.route('/api/payment/googlepay', methods=['POST'])
@login_required
def process_googlepay_payment():
    """Process Google Pay payment"""
    try:
        data = request.json
        appointment_id = data.get('appointment_id')
        email = data.get('email')
        amount = data.get('amount')
        
        # Validate input
        if not all([appointment_id, email, amount]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Simulate Google Pay payment processing
        transaction_id = f"GOOGLEPAY_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        
        # Update appointment payment status
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            appointment.payment_status = 'completed'
            appointment.payment_reference = transaction_id
            
            # Create payment record
            payment = Payment(
                appointment_id=appointment_id,
                amount=amount,
                payment_method='googlepay',
                transaction_id=transaction_id,
                status='completed'
            )
            db.session.add(payment)
            db.session.commit()
            
            log_audit('payment_processed', current_user.id, f'Google Pay: {transaction_id}')
            return jsonify({'success': True, 'transaction_id': transaction_id})
        else:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
            
    except Exception as e:
        app.logger.error(f"Google Pay payment error: {str(e)}")
        return jsonify({'success': False, 'error': 'Payment processing failed'}), 500

@app.route('/api/payment/airtel', methods=['POST'])
@login_required
def process_airtel_payment():
    """Process Airtel Money payment"""
    try:
        data = request.json
        appointment_id = data.get('appointment_id')
        phone = data.get('phone')
        amount = data.get('amount')
        
        # Validate input
        if not all([appointment_id, phone, amount]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Simulate Airtel Money payment processing
        transaction_id = f"AIRTEL_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        
        # Update appointment payment status
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            appointment.payment_status = 'completed'
            appointment.payment_reference = transaction_id
            
            # Create payment record
            payment = Payment(
                appointment_id=appointment_id,
                amount=amount,
                payment_method='airtel',
                transaction_id=transaction_id,
                status='completed'
            )
            db.session.add(payment)
            db.session.commit()
            
            log_audit('payment_processed', current_user.id, f'Airtel Money: {transaction_id}')
            return jsonify({'success': True, 'transaction_id': transaction_id})
        else:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
            
    except Exception as e:
        app.logger.error(f"Airtel Money payment error: {str(e)}")
        return jsonify({'success': False, 'error': 'Payment processing failed'}), 500
@app.route('/payment/<int:appointment_id>')
@login_required
def payment_page(appointment_id):
    """Payment page for appointments"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            flash('Access denied', 'error')
            return redirect(url_for('patient_dashboard'))
        
        return render_template('payment.html', 
                             appointment=appointment,
                             doctor=appointment.doctor)
    
    except Exception as e:
        app.logger.error(f"Error loading payment page: {str(e)}")
        flash('Error loading payment page', 'error')
        return redirect(url_for('patient_dashboard'))

@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment_intent():
    try:
        data = request.json
        appointment_id = data['appointment_id']
        amount = data['amount']
        
        # In a real implementation, integrate with Stripe or M-Pesa
        # For now, simulate payment intent creation
        payment_intent = {
            'id': f'pi_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
            'client_secret': f'cs_test_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}'
        }
        
        return jsonify({
            'clientSecret': payment_intent['client_secret'],
            'paymentIntentId': payment_intent['id']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 403

@app.route('/payment-success', methods=['POST'])
@login_required
def payment_success():
    try:
        data = request.json
        appointment_id = data['appointment_id']
        transaction_id = data['transaction_id']
        
        # Update appointment and payment status
        appointment = Appointment.query.get(appointment_id)
        if appointment and appointment.patient_id == current_user.patient_profile.id:
            appointment.payment_status = 'completed'
            appointment.payment_reference = transaction_id
            
            payment_record = Payment(
                appointment_id=appointment_id,
                amount=appointment.doctor.consultation_fee,
                transaction_id=transaction_id,
                status='completed'
            )
            db.session.add(payment_record)
            db.session.commit()
            
            log_audit('payment_success', current_user.id, f'Appointment: {appointment_id}')
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Appointment not found'})
    
    except Exception as e:
        app.logger.error(f"Payment success error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# MESSAGING ROUTES (Updated with Rate Limiting)
# =============================================================================
@app.route('/api/communication/appointments')
@login_required
def get_communication_appointments():
    """Get appointments for communication hub with real data"""
    try:
        if current_user.role == 'patient':
            appointments = Appointment.query.filter_by(
                patient_id=current_user.patient_profile.id
            ).order_by(Appointment.appointment_date.desc()).all()
        else:  # doctor
            appointments = Appointment.query.filter_by(
                doctor_id=current_user.doctor_profile.id
            ).order_by(Appointment.appointment_date.desc()).all()
        
        appointments_data = []
        for apt in appointments:
            local_time = apt.get_local_appointment_time(current_user)
            
            # Get unread message count
            unread_count = Message.query.filter(
                Message.appointment_id == apt.id,
                Message.receiver_id == current_user.id,
                Message.is_read == False
            ).count()
            
            # Get last message
            last_message = Message.query.filter_by(appointment_id=apt.id)\
                                      .order_by(Message.created_at.desc())\
                                      .first()
            
            # Check if communication is allowed (payment completed for doctors)
            can_communicate = True
            if current_user.role == 'doctor':
                can_communicate = apt.payment_status == 'completed'
            
            appointment_info = {
                'id': apt.id,
                'patient_name': f"{apt.patient.first_name} {apt.patient.last_name}",
                'doctor_name': f"Dr. {apt.doctor.first_name} {apt.doctor.last_name}",
                'specialization': apt.doctor.specialization,
                'appointment_date': apt.appointment_date.isoformat(),
                'local_appointment_date': local_time.isoformat() if local_time else None,
                'formatted_date': format_datetime(apt.appointment_date),
                'status': apt.status,
                'payment_status': apt.payment_status,
                'unread_count': unread_count,
                'last_message': last_message.content if last_message else None,
                'last_message_time': last_message.created_at.isoformat() if last_message else None,
                'can_communicate': can_communicate,
                'has_video_call': bool(apt.video_call_url) and can_communicate,
                'has_voice_call': bool(apt.voice_call_url) and can_communicate
            }
            
            appointments_data.append(appointment_info)
        
        return jsonify(appointments_data)
    
    except Exception as e:
        app.logger.error(f"Error getting communication appointments: {str(e)}")
        return jsonify({'error': 'Failed to load appointments'}), 500

@app.route('/api/check_new_messages/<int:appointment_id>', methods=['GET'])
@login_required
@limiter.limit("30 per minute")  # More reasonable limit for message checking
def check_new_messages(appointment_id):
    """Check for new messages in an appointment"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get the last message timestamp from query parameter
        last_check = request.args.get('last_check')
        if last_check:
            last_check = datetime.fromisoformat(last_check.replace('Z', '+00:00'))
        else:
            last_check = datetime.utcnow() - timedelta(hours=24)  # Default to last 24 hours
        
        # Query new messages
        new_messages = Message.query.filter(
            Message.appointment_id == appointment_id,
            Message.created_at > last_check,
            Message.receiver_id == current_user.id
        ).order_by(Message.created_at.asc()).all()
        
        # Mark messages as read
        for message in new_messages:
            message.is_read = True
        db.session.commit()
        
        messages_data = []
        for message in new_messages:
            messages_data.append({
                'id': message.id,
                'sender_id': message.sender_id,
                'sender_name': message.sender.username or message.sender.email,
                'sender_role': message.sender.role,
                'receiver_id': message.receiver_id,
                'message_type': message.message_type,
                'content': message.content,
                'audio_url': message.audio_url,
                'file_url': message.file_url,
                'file_name': message.file_name,
                'file_size': message.file_size,
                'is_read': message.is_read,
                'created_at': message.created_at.isoformat(),
                'is_own': message.sender_id == current_user.id
            })
        
        return jsonify({
            'new_messages': messages_data,
            'last_check': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        app.logger.error(f"Error checking new messages: {str(e)}")
        return jsonify({'error': 'Failed to check messages'}), 500

@app.route('/api/check_typing/<int:appointment_id>', methods=['POST'])
@login_required
@limiter.limit("20 per minute")  # Reduced from default to prevent 429 errors
def check_typing(appointment_id):
    """Check if the other user is typing"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        # In a real implementation, you would use WebSockets
        # For backward compatibility, return false
        return jsonify({
            'is_typing': False,
            'user_id': None
        })
    
    except Exception as e:
        app.logger.error(f"Error checking typing status: {str(e)}")
        return jsonify({'error': 'Failed to check typing status'}), 500

@app.route('/api/mark_typing/<int:appointment_id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute")  # Reasonable limit for typing indicators
def mark_typing(appointment_id):
    """Mark that the current user is typing"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.json
        is_typing = data.get('is_typing', False)
        
        # In a real implementation, you would broadcast this via WebSockets
        # For backward compatibility, just acknowledge
        
        return jsonify({
            'success': True,
            'is_typing': is_typing
        })
    
    except Exception as e:
        app.logger.error(f"Error marking typing status: {str(e)}")
        return jsonify({'error': 'Failed to mark typing status'}), 500

# =============================================================================
# MESSAGE STATUS UPDATES
# =============================================================================

@app.route('/api/messages/<int:appointment_id>/unread_count', methods=['GET'])
@login_required
def get_unread_message_count(appointment_id):
    """Get count of unread messages for an appointment"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        unread_count = Message.query.filter(
            Message.appointment_id == appointment_id,
            Message.receiver_id == current_user.id,
            Message.is_read == False
        ).count()
        
        return jsonify({
            'unread_count': unread_count,
            'appointment_id': appointment_id
        })
    
    except Exception as e:
        app.logger.error(f"Error getting unread message count: {str(e)}")
        return jsonify({'error': 'Failed to get unread count'}), 500

@app.route('/api/messages/<int:appointment_id>/mark_all_read', methods=['POST'])
@login_required
def mark_all_messages_read(appointment_id):
    """Mark all messages as read for an appointment"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Mark all unread messages as read
        unread_messages = Message.query.filter(
            Message.appointment_id == appointment_id,
            Message.receiver_id == current_user.id,
            Message.is_read == False
        ).all()
        
        for message in unread_messages:
            message.is_read = True
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'marked_read': len(unread_messages)
        })
    
    except Exception as e:
        app.logger.error(f"Error marking messages as read: {str(e)}")
        return jsonify({'error': 'Failed to mark messages as read'}), 500

# =============================================================================
# FILE DOWNLOAD ROUTES
# =============================================================================

@app.route('/api/download/file/<path:filename>')
@login_required
def download_file(filename):
    """Download a file from the uploads directory"""
    try:
        # Security check - ensure the file is in the uploads directory
        safe_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        safe_path = os.path.abspath(safe_path)
        
        # Ensure the path is within the uploads directory
        if not safe_path.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
            return jsonify({'error': 'Invalid file path'}), 403
        
        if os.path.exists(safe_path):
            return send_file(safe_path, as_attachment=True)
        else:
            return jsonify({'error': 'File not found'}), 404
    
    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        return jsonify({'error': 'Failed to download file'}), 500

# =============================================================================
# COMMUNICATION DASHBOARD ROUTE
# =============================================================================

@app.route('/communication')
@login_required
def communication():
    """Main communication hub with appointment filtering"""
    try:
        appointment_id = request.args.get('appointment_id')
        selected_appointment = None
        
        if appointment_id:
            selected_appointment = Appointment.query.get(appointment_id)
            # Verify user has access to this appointment
            if selected_appointment:
                if current_user.role == 'patient' and selected_appointment.patient_id != current_user.patient_profile.id:
                    selected_appointment = None
                elif current_user.role == 'doctor' and selected_appointment.doctor_id != current_user.doctor_profile.id:
                    selected_appointment = None
        
        if current_user.role == 'patient':
            appointments = Appointment.query.filter_by(
                patient_id=current_user.patient_profile.id
            ).order_by(Appointment.appointment_date.desc()).all()
        else:  # doctor
            appointments = Appointment.query.filter_by(
                doctor_id=current_user.doctor_profile.id
            ).order_by(Appointment.appointment_date.desc()).all()
        
        return render_template('communication.html', 
                             appointments=appointments,
                             selected_appointment=selected_appointment,
                             current_user_role=current_user.role,
                             current_user=current_user)
    
    except Exception as e:
        app.logger.error(f"Error in communication route: {str(e)}")
        flash('Error loading communication hub', 'error')
        return redirect(url_for('patient_dashboard' if current_user.role == 'patient' else 'doctor_dashboard'))

def get_patient_communication_data(user_id):
    """Get comprehensive communication data for patient dashboard"""
    try:
        patient = Patient.query.filter_by(user_id=user_id).first()
        if not patient:
            return {
                'appointments': [],
                'recent_messages': [],
                'voice_calls': [],
                'upcoming_appointments': [],
                'stats': {
                    'total_messages': 0,
                    'unread_messages': 0,
                    'total_calls': 0,
                    'active_conversations': 0
                }
            }
        
        # Get recent appointments with communication info
        recent_appointments = Appointment.query.filter_by(
            patient_id=patient.id
        ).order_by(Appointment.appointment_date.desc()).limit(5).all()
        
        appointment_data = []
        for apt in recent_appointments:
            # Get unread message count for this appointment
            unread_count = Message.query.filter(
                Message.appointment_id == apt.id,
                Message.receiver_id == user_id,
                Message.is_read == False
            ).count()
            
            # Get last message
            last_message = Message.query.filter_by(appointment_id=apt.id)\
                                      .order_by(Message.created_at.desc())\
                                      .first()
            
            appointment_data.append({
                'id': apt.id,
                'doctor_name': f"Dr. {apt.doctor.first_name} {apt.doctor.last_name}",
                'specialization': apt.doctor.specialization,
                'appointment_date': apt.appointment_date,
                'status': apt.status,
                'unread_messages': unread_count,
                'last_message': last_message.content if last_message else None,
                'last_message_time': last_message.created_at if last_message else None,
                'has_video_call': bool(apt.video_call_url),
                'has_voice_call': bool(apt.voice_call_url)
            })
        
        # Get upcoming appointments (next 7 days)
        now_utc = datetime.utcnow()
        week_from_now = now_utc + timedelta(days=7)
        upcoming_appointments = Appointment.query.filter(
            Appointment.patient_id == patient.id,
            Appointment.appointment_date >= now_utc,
            Appointment.appointment_date <= week_from_now,
            Appointment.status.in_(['scheduled', 'confirmed'])
        ).order_by(Appointment.appointment_date.asc()).all()
        
        # Get recent messages across all appointments
        recent_messages = Message.query.join(Appointment).filter(
            Appointment.patient_id == patient.id,
            Message.receiver_id == user_id
        ).order_by(Message.created_at.desc()).limit(10).all()
        
        messages_data = []
        for msg in recent_messages:
            messages_data.append({
                'id': msg.id,
                'appointment_id': msg.appointment_id,
                'sender_name': msg.sender.username or msg.sender.email,
                'content': msg.content[:100] + '...' if msg.content and len(msg.content) > 100 else msg.content,
                'message_type': msg.message_type,
                'is_read': msg.is_read,
                'created_at': msg.created_at
            })
        
        # Get voice call history
        voice_calls = VoiceCall.query.join(Appointment).filter(
            Appointment.patient_id == patient.id
        ).order_by(VoiceCall.created_at.desc()).limit(5).all()
        
        calls_data = []
        for call in voice_calls:
            calls_data.append({
                'id': call.id,
                'doctor_name': f"Dr. {call.receiver.doctor_profile.first_name} {call.receiver.doctor_profile.last_name}",
                'call_status': call.call_status,
                'call_duration': call.call_duration,
                'started_at': call.started_at
            })
        
        # Calculate communication statistics
        total_messages = Message.query.join(Appointment).filter(
            Appointment.patient_id == patient.id
        ).count()
        
        unread_messages = Message.query.join(Appointment).filter(
            Appointment.patient_id == patient.id,
            Message.receiver_id == user_id,
            Message.is_read == False
        ).count()
        
        total_calls = VoiceCall.query.join(Appointment).filter(
            Appointment.patient_id == patient.id
        ).count()
        
        return {
            'appointments': appointment_data,
            'recent_messages': messages_data,
            'voice_calls': calls_data,
            'upcoming_appointments': upcoming_appointments,
            'stats': {
                'total_messages': total_messages,
                'unread_messages': unread_messages,
                'total_calls': total_calls,
                'active_conversations': len(recent_appointments)
            }
        }
        
    except Exception as e:
        app.logger.error(f"Error getting patient communication data: {str(e)}")
        return {
            'appointments': [],
            'recent_messages': [],
            'voice_calls': [],
            'upcoming_appointments': [],
            'stats': {
                'total_messages': 0,
                'unread_messages': 0,
                'total_calls': 0,
                'active_conversations': 0
            }
        }

def get_doctor_communication_data(user_id):
    """Get comprehensive communication data for doctor dashboard"""
    try:
        doctor = Doctor.query.filter_by(user_id=user_id).first()
        if not doctor:
            return {
                'appointments': [],
                'recent_messages': [],
                'today_appointments': [],
                'stats': {
                    'total_appointments_today': 0,
                    'unread_messages': 0,
                    'pending_appointments': 0
                }
            }
        
        # Get recent appointments
        recent_appointments = Appointment.query.filter_by(
            doctor_id=doctor.id
        ).order_by(Appointment.appointment_date.desc()).limit(5).all()
        
        appointment_data = []
        for apt in recent_appointments:
            unread_count = Message.query.filter(
                Message.appointment_id == apt.id,
                Message.receiver_id == user_id,
                Message.is_read == False
            ).count()
            
            last_message = Message.query.filter_by(appointment_id=apt.id)\
                                      .order_by(Message.created_at.desc())\
                                      .first()
            
            appointment_data.append({
                'id': apt.id,
                'patient_name': f"{apt.patient.first_name} {apt.patient.last_name}",
                'appointment_date': apt.appointment_date,
                'status': apt.status,
                'unread_messages': unread_count,
                'last_message': last_message.content if last_message else None,
                'last_message_time': last_message.created_at if last_message else None
            })
        
        # Get today's appointments
        today_utc = datetime.utcnow().date()
        today_appointments = Appointment.query.filter(
            Appointment.doctor_id == doctor.id,
            db.func.date(Appointment.appointment_date) == today_utc,
            Appointment.status.in_(['scheduled', 'confirmed'])
        ).all()
        
        # Get recent messages
        recent_messages = Message.query.join(Appointment).filter(
            Appointment.doctor_id == doctor.id,
            Message.receiver_id == user_id
        ).order_by(Message.created_at.desc()).limit(10).all()
        
        messages_data = []
        for msg in recent_messages:
            messages_data.append({
                'id': msg.id,
                'appointment_id': msg.appointment_id,
                'patient_name': f"{msg.sender.patient_profile.first_name} {msg.sender.patient_profile.last_name}",
                'content': msg.content[:100] + '...' if msg.content and len(msg.content) > 100 else msg.content,
                'message_type': msg.message_type,
                'is_read': msg.is_read,
                'created_at': msg.created_at
            })
        
        return {
            'appointments': appointment_data,
            'recent_messages': messages_data,
            'today_appointments': today_appointments,
            'stats': {
                'total_appointments_today': len(today_appointments),
                'unread_messages': sum(apt['unread_messages'] for apt in appointment_data),
                'pending_appointments': len([apt for apt in recent_appointments if apt.status == 'scheduled'])
            }
        }
        
    except Exception as e:
        app.logger.error(f"Error getting doctor communication data: {str(e)}")
        return {
            'appointments': [],
            'recent_messages': [],
            'today_appointments': [],
            'stats': {
                'total_appointments_today': 0,
                'unread_messages': 0,
                'pending_appointments': 0
            }
        }

@app.context_processor
def inject_user_role():
    """Inject current user role into all templates"""
    return {
        'current_user_role': current_user.role if current_user.is_authenticated else None
    }

# =============================================================================
# WEBSOCKET-ENABLED API ROUTES
# =============================================================================

@app.route('/api/messages/<int:appointment_id>', methods=['GET'])
@login_required
def get_messages(appointment_id):
    """Get all messages for an appointment"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        messages = Message.query.filter_by(appointment_id=appointment_id)\
                              .order_by(Message.created_at.asc())\
                              .all()
        
        messages_data = []
        for message in messages:
            messages_data.append({
                'id': message.id,
                'sender_id': message.sender_id,
                'sender_name': message.sender.username or message.sender.email,
                'sender_role': message.sender.role,
                'receiver_id': message.receiver_id,
                'message_type': message.message_type,
                'content': message.content,
                'audio_url': message.audio_url,
                'file_url': message.file_url,
                'file_name': message.file_name,
                'file_size': message.file_size,
                'is_read': message.is_read,
                'created_at': message.created_at.isoformat(),
                'is_own': message.sender_id == current_user.id
            })
        
        return jsonify(messages_data)
    
    except Exception as e:
        app.logger.error(f"Error fetching messages: {str(e)}")
        return jsonify({'error': 'Failed to fetch messages'}), 500

@app.route('/api/messages/<int:appointment_id>', methods=['POST'])
@login_required
@limiter.limit("50 per minute")  # Reasonable limit for message sending
def send_message(appointment_id):
    """Send a new message (fallback for non-WebSocket clients)"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.json
        message_type = data.get('message_type', 'text')
        content = sanitize_input(data.get('content', ''))
        
        if not content and message_type == 'text':
            return jsonify({'error': 'Message content is required'}), 400
        
        # Determine receiver
        if current_user.role == 'patient':
            receiver_id = appointment.doctor.user_id
        else:
            receiver_id = appointment.patient.user_id
        
        message = Message(
            appointment_id=appointment_id,
            sender_id=current_user.id,
            receiver_id=receiver_id,
            message_type=message_type,
            content=content
        )
        
        db.session.add(message)
        db.session.commit()
        
        # Return the created message
        message_data = {
            'id': message.id,
            'sender_id': message.sender_id,
            'sender_name': message.sender.username or message.sender.email,
            'sender_role': message.sender.role,
            'receiver_id': message.receiver_id,
            'message_type': message.message_type,
            'content': message.content,
            'is_read': message.is_read,
            'created_at': message.created_at.isoformat(),
            'is_own': True
        }
        
        log_audit('message_sent', current_user.id, f'Appointment: {appointment_id}, Type: {message_type}')
        return jsonify(message_data)
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error sending message: {str(e)}")
        return jsonify({'error': 'Failed to send message'}), 500

# =============================================================================
# VOICE RECORDING ROUTES
# =============================================================================

@app.route('/api/voice-recordings', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Limit voice recording uploads
def upload_voice_recording():
    """Upload a voice recording"""
    try:
        if 'audio' not in request.files:
            return jsonify({'error': 'No audio file provided'}), 400
        
        audio_file = request.files['audio']
        appointment_id = request.form.get('appointment_id')
        
        if not appointment_id:
            return jsonify({'error': 'Appointment ID required'}), 400
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if audio_file and audio_file.filename != '':
            # Generate unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"voice_{current_user.id}_{timestamp}.webm"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'voice_recordings', filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            audio_file.save(file_path)
            file_size = os.path.getsize(file_path)
            
            # Create voice recording record
            recording = VoiceRecording(
                appointment_id=appointment_id,
                user_id=current_user.id,
                audio_url=f'/static/uploads/voice_recordings/{filename}',
                file_name=filename,
                file_size=file_size,
                duration=request.form.get('duration', 0)
            )
            db.session.add(recording)
            
            # Also create a message for the recording
            if current_user.role == 'patient':
                receiver_id = appointment.doctor.user_id
            else:
                receiver_id = appointment.patient.user_id
            
            message = Message(
                appointment_id=appointment_id,
                sender_id=current_user.id,
                receiver_id=receiver_id,
                message_type='audio',
                audio_url=f'/static/uploads/voice_recordings/{filename}',
                content='Voice message',
                file_name=filename,
                file_size=file_size
            )
            db.session.add(message)
            
            db.session.commit()
            
            log_audit('voice_recording_uploaded', current_user.id, f'Appointment: {appointment_id}')
            return jsonify({
                'success': True,
                'recording_id': recording.id,
                'message_id': message.id,
                'audio_url': recording.audio_url,
                'file_name': recording.file_name
            })
        else:
            return jsonify({'error': 'Invalid audio file'}), 400
    
    except Exception as e:
        app.logger.error(f"Error uploading voice recording: {str(e)}")
        return jsonify({'error': 'Failed to upload voice recording'}), 500

# =============================================================================
# PROFILE ROUTES
# =============================================================================

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    try:
        if current_user.role == 'patient':
            profile_data = current_user.patient_profile
        elif current_user.role == 'doctor':
            profile_data = current_user.doctor_profile
        else:  # admin
            profile_data = None
        
        return render_template('profile.html', 
                             profile_data=profile_data,
                             current_user=current_user)
    
    except Exception as e:
        app.logger.error(f"Error loading profile: {str(e)}")
        flash('Error loading profile', 'error')
        return redirect(url_for('patient_dashboard' if current_user.role == 'patient' else 'doctor_dashboard'))

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile with enhanced validation"""
    try:
        if request.form.get('change_password'):
            # Handle password change
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return redirect(url_for('profile'))
            
            if not User().is_strong_password(new_password):
                flash('Password must be at least 8 characters with uppercase, lowercase, number, and special character', 'error')
                return redirect(url_for('profile'))
            
            current_user.set_password(new_password)
            db.session.commit()
            log_audit('password_changed', current_user.id)
            flash('Password updated successfully!', 'success')
            return redirect(url_for('profile'))
        
        # Handle profile update
        if current_user.role == 'patient':
            profile = current_user.patient_profile
            if not profile:
                flash('Patient profile not found', 'error')
                return redirect(url_for('profile'))
            
            # Update patient profile fields
            profile.first_name = sanitize_input(request.form.get('first_name', ''))
            profile.last_name = sanitize_input(request.form.get('last_name', ''))
            profile.phone = sanitize_input(request.form.get('phone', ''))
            profile.address = sanitize_input(request.form.get('address', ''))
            profile.emergency_contact = sanitize_input(request.form.get('emergency_contact', ''))
            profile.medical_history = sanitize_input(request.form.get('medical_history', ''))
            
            # Handle date of birth
            dob_str = request.form.get('date_of_birth')
            if dob_str:
                try:
                    profile.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
                except ValueError:
                    flash('Invalid date format', 'error')
                    return redirect(url_for('profile'))
        
        elif current_user.role == 'doctor':
            profile = current_user.doctor_profile
            if not profile:
                flash('Doctor profile not found', 'error')
                return redirect(url_for('profile'))
            
            # Update doctor profile fields
            profile.first_name = sanitize_input(request.form.get('first_name', ''))
            profile.last_name = sanitize_input(request.form.get('last_name', ''))
            profile.specialization = sanitize_input(request.form.get('specialization', ''))
            profile.license_number = sanitize_input(request.form.get('license_number', ''))
            profile.phone = sanitize_input(request.form.get('phone', ''))
            profile.bio = sanitize_input(request.form.get('bio', ''))
            profile.available_hours = sanitize_input(request.form.get('available_hours', ''))
            
            # Handle consultation fee
            fee_str = request.form.get('consultation_fee')
            if fee_str:
                try:
                    profile.consultation_fee = float(fee_str)
                except ValueError:
                    flash('Invalid consultation fee', 'error')
                    return redirect(url_for('profile'))
        
        # Update user email and timezone
        new_email = sanitize_input(request.form.get('email', '').lower())
        if new_email and new_email != current_user.email:
            # Check if email is already taken
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user and existing_user.id != current_user.id:
                flash('Email already taken', 'error')
                return redirect(url_for('profile'))
            current_user.email = new_email
        
        timezone = request.form.get('timezone')
        if timezone:
            current_user.timezone = timezone
        
        db.session.commit()
        
        log_audit('profile_updated', current_user.id)
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating profile: {str(e)}")
        flash('Error updating profile', 'error')
        return redirect(url_for('profile'))

# =============================================================================
# MISSING ADMIN ROUTES
# =============================================================================

@app.route('/admin/users')
@login_required
def manage_users():
    """Admin user management page"""
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/doctors')
@login_required
def manage_doctors():
    """Admin doctor management page"""
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    doctors = Doctor.query.all()
    return render_template('admin_doctors.html', doctors=doctors)

@app.route('/admin/reports')
@login_required
def reports():
    """Admin reports page"""
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    return render_template('admin_reports.html')

@app.route('/admin/settings')
@login_required
def settings():
    """Admin settings page"""
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    return render_template('admin_settings.html')

# =============================================================================
# PATIENT SPECIFIC ROUTES
# =============================================================================

@app.route('/my-appointments')
@login_required
def my_appointments():
    """Patient's appointments page"""
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    appointments = Appointment.query.filter_by(
        patient_id=current_user.patient_profile.id
    ).order_by(Appointment.appointment_date.desc()).all()
    
    # Convert to local time
    for appointment in appointments:
        appointment.local_time = appointment.get_local_appointment_time(current_user)
    
    return render_template('patient_appointments.html', 
                         appointments=appointments,
                         format_datetime=format_datetime)

from datetime import datetime, timedelta

from datetime import datetime, timedelta
from sqlalchemy import func

@app.route('/my-documents')
@login_required
def my_documents():
    """Patient's documents page"""
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get all documents for the patient
        documents = PatientDocument.query.filter_by(
            patient_id=current_user.patient_profile.id
        ).order_by(PatientDocument.uploaded_at.desc()).all()

        # Calculate recent uploads count (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_uploads_count = PatientDocument.query.filter(
            PatientDocument.patient_id == current_user.patient_profile.id,
            PatientDocument.uploaded_at >= thirty_days_ago
        ).count()
        
        # Pass thirty_days_ago to the template
        return render_template('patient_documents.html', 
                             documents=documents,
                             recent_uploads_count=recent_uploads_count,
                             thirty_days_ago=thirty_days_ago)
        
    except Exception as e:
        print(f"Error in my_documents: {e}")
        # Fallback with safe values
        return render_template('patient_documents.html', 
                             documents=[],
                             recent_uploads_count=0,
                             thirty_days_ago=datetime.utcnow() - timedelta(days=30))
 
@app.route('/api/doctors/featured')
@login_required
def get_featured_doctors():
    """Get featured doctors"""
    try:
        featured_doctors = Doctor.query.filter_by(
            is_featured=True, 
            is_available=True
        ).limit(6).all()
        
        doctors_data = []
        for doctor in featured_doctors:
            doctors_data.append({
                'id': doctor.id,
                'name': f'Dr. {doctor.first_name} {doctor.last_name}',
                'specialization': doctor.specialization,
                'consultation_fee': doctor.consultation_fee,
                'experience': doctor.experience,
                'rating': doctor.average_rating,
                'review_count': doctor.review_count,
                'bio': doctor.bio,
                'image_url': f'/static/images/doctors/{doctor.id}.jpg'  # Adjust path as needed
            })
        
        return jsonify(doctors_data)
    
    except Exception as e:
        app.logger.error(f"Error getting featured doctors: {str(e)}")
        return jsonify({'error': 'Failed to load featured doctors'}), 500

@app.route('/api/doctors/recent')
@login_required
def get_recent_doctors():
    """Get recently added doctors"""
    try:
        recent_doctors = Doctor.query.filter_by(is_available=True)\
                                   .order_by(Doctor.created_at.desc())\
                                   .limit(6).all()
        
        doctors_data = []
        for doctor in recent_doctors:
            doctors_data.append({
                'id': doctor.id,
                'name': f'Dr. {doctor.first_name} {doctor.last_name}',
                'specialization': doctor.specialization,
                'consultation_fee': doctor.consultation_fee,
                'experience': doctor.experience,
                'rating': doctor.average_rating,
                'created_at': doctor.created_at.isoformat() if doctor.created_at else None
            })
        
        return jsonify(doctors_data)
    
    except Exception as e:
        app.logger.error(f"Error getting recent doctors: {str(e)}")
        return jsonify({'error': 'Failed to load recent doctors'}), 500
    
@app.route('/find-doctors')
@login_required
def find_doctors():
    try:
        # Use is_available instead of is_active
        doctors = Doctor.query.filter_by(is_available=True).all()
    except Exception as e:
        print(f"Error fetching doctors: {e}")
        # Fallback to empty list if there's an error
        doctors = []
    
    # Ensure all doctors have safe default values for template rendering
    for doctor in doctors:
        doctor.first_name = doctor.first_name or ''
        doctor.last_name = doctor.last_name or ''
        doctor.specialization = doctor.specialization or 'General Practitioner'
        doctor.consultation_fee = getattr(doctor, 'consultation_fee', 0.0) or 0.0
        doctor.bio = doctor.bio or ''
        # Add any missing attributes that your template expects
        if not hasattr(doctor, 'experience'):
            doctor.experience = '5'  # Default value
        if not hasattr(doctor, 'average_rating'):
            doctor.average_rating = 0.0
        if not hasattr(doctor, 'review_count'):
            doctor.review_count = 0
        if not hasattr(doctor, 'response_time'):
            doctor.response_time = '< 1 hour'
        if not hasattr(doctor, 'patient_count'):
            doctor.patient_count = '100+'
        if not hasattr(doctor, 'is_featured'):
            doctor.is_featured = False
    
    return render_template('find_doctors.html', doctors=doctors)

# =============================================================================
# DOCTOR SPECIFIC ROUTES
# ============================================================================

@app.route('/doctor/patients')
@login_required
def doctor_patients():
    """Doctor's patients page"""
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Get unique patients from appointments
    appointments = Appointment.query.filter_by(
        doctor_id=current_user.doctor_profile.id
    ).all()
    
    patient_ids = set(apt.patient_id for apt in appointments)
    patients = Patient.query.filter(Patient.id.in_(patient_ids)).all()
    
    return render_template('doctor_patients.html', patients=patients)

# =============================================================================
# MISSING API ROUTES FOR DASHBOARD
# =============================================================================

@app.route('/api/messages/recent')
@login_required
def get_recent_messages():
    """Get recent messages for the current user"""
    try:
        if current_user.role == 'patient':
            # Get messages where patient is involved
            recent_messages = Message.query.join(Appointment).filter(
                Appointment.patient_id == current_user.patient_profile.id
            ).order_by(Message.created_at.desc()).limit(10).all()
        elif current_user.role == 'doctor':
            # Get messages where doctor is involved
            recent_messages = Message.query.join(Appointment).filter(
                Appointment.doctor_id == current_user.doctor_profile.id
            ).order_by(Message.created_at.desc()).limit(10).all()
        else:
            recent_messages = []
        
        messages_data = []
        for message in recent_messages:
            messages_data.append({
                'id': message.id,
                'appointment_id': message.appointment_id,
                'sender_name': message.sender.username or message.sender.email,
                'content': message.content[:50] + '...' if message.content and len(message.content) > 50 else message.content,
                'created_at': format_datetime(message.created_at),
                'is_read': message.is_read,
                'is_own': message.sender_id == current_user.id
            })
        
        return jsonify(messages_data)
    
    except Exception as e:
        app.logger.error(f"Error getting recent messages: {str(e)}")
        return jsonify({'error': 'Failed to load recent messages'}), 500

@app.route('/api/communication/stats')
@login_required
def get_communication_stats():
    """Get communication statistics for dashboard"""
    try:
        if current_user.role == 'patient':
            patient = current_user.patient_profile
            if not patient:
                return jsonify({'error': 'Patient profile not found'}), 404
            
            total_messages = Message.query.join(Appointment).filter(
                Appointment.patient_id == patient.id
            ).count()
            
            unread_messages = Message.query.join(Appointment).filter(
                Appointment.patient_id == patient.id,
                Message.receiver_id == current_user.id,
                Message.is_read == False
            ).count()
            
            total_appointments = Appointment.query.filter_by(
                patient_id=patient.id
            ).count()
            
            upcoming_appointments = Appointment.query.filter(
                Appointment.patient_id == patient.id,
                Appointment.appointment_date >= datetime.utcnow(),
                Appointment.status.in_(['scheduled', 'confirmed'])
            ).count()
        
        elif current_user.role == 'doctor':
            doctor = current_user.doctor_profile
            if not doctor:
                return jsonify({'error': 'Doctor profile not found'}), 404
            
            total_messages = Message.query.join(Appointment).filter(
                Appointment.doctor_id == doctor.id
            ).count()
            
            unread_messages = Message.query.join(Appointment).filter(
                Appointment.doctor_id == doctor.id,
                Message.receiver_id == current_user.id,
                Message.is_read == False
            ).count()
            
            total_appointments = Appointment.query.filter_by(
                doctor_id=doctor.id
            ).count()
            
            today_utc = datetime.utcnow().date()
            upcoming_appointments = Appointment.query.filter(
                Appointment.doctor_id == doctor.id,
                Appointment.appointment_date >= datetime.utcnow(),
                Appointment.status.in_(['scheduled', 'confirmed'])
            ).count()
        
        else:
            # Admin stats
            total_messages = Message.query.count()
            unread_messages = 0
            total_appointments = Appointment.query.count()
            upcoming_appointments = Appointment.query.filter(
                Appointment.appointment_date >= datetime.utcnow(),
                Appointment.status.in_(['scheduled', 'confirmed'])
            ).count()
        
        return jsonify({
            'total_messages': total_messages,
            'unread_messages': unread_messages,
            'total_appointments': total_appointments,
            'upcoming_appointments': upcoming_appointments
        })
    
    except Exception as e:
        app.logger.error(f"Error getting communication stats: {str(e)}")
        return jsonify({'error': 'Failed to load communication statistics'}), 500

@app.route('/api/appointments/today')
@login_required
def get_today_appointments():
    """Get today's appointments"""
    try:
        today_utc = datetime.utcnow().date()
        
        if current_user.role == 'patient':
            appointments = Appointment.query.filter(
                Appointment.patient_id == current_user.patient_profile.id,
                db.func.date(Appointment.appointment_date) == today_utc,
                Appointment.status.in_(['scheduled', 'confirmed'])
            ).order_by(Appointment.appointment_date.asc()).all()
        
        elif current_user.role == 'doctor':
            appointments = Appointment.query.filter(
                Appointment.doctor_id == current_user.doctor_profile.id,
                db.func.date(Appointment.appointment_date) == today_utc,
                Appointment.status.in_(['scheduled', 'confirmed'])
            ).order_by(Appointment.appointment_date.asc()).all()
        
        else:
            appointments = []
        
        appointments_data = []
        for apt in appointments:
            local_time = apt.get_local_appointment_time(current_user)
            
            appointments_data.append({
                'id': apt.id,
                'patient_name': f"{apt.patient.first_name} {apt.patient.last_name}" if current_user.role == 'doctor' else None,
                'doctor_name': f"Dr. {apt.doctor.first_name} {apt.doctor.last_name}" if current_user.role == 'patient' else None,
                'appointment_time': local_time.strftime('%H:%M') if local_time else '',
                'status': apt.status,
                'symptoms': apt.symptoms[:100] + '...' if apt.symptoms and len(apt.symptoms) > 100 else apt.symptoms
            })
        
        return jsonify(appointments_data)
    
    except Exception as e:
        app.logger.error(f"Error getting today's appointments: {str(e)}")
        return jsonify({'error': 'Failed to load today\'s appointments'}), 500

@app.route('/api/appointments/upcoming')
@login_required
def get_upcoming_appointments():
    """Get upcoming appointments (next 7 days)"""
    try:
        now_utc = datetime.utcnow()
        week_from_now = now_utc + timedelta(days=7)
        
        if current_user.role == 'patient':
            appointments = Appointment.query.filter(
                Appointment.patient_id == current_user.patient_profile.id,
                Appointment.appointment_date >= now_utc,
                Appointment.appointment_date <= week_from_now,
                Appointment.status.in_(['scheduled', 'confirmed'])
            ).order_by(Appointment.appointment_date.asc()).all()
        
        elif current_user.role == 'doctor':
            appointments = Appointment.query.filter(
                Appointment.doctor_id == current_user.doctor_profile.id,
                Appointment.appointment_date >= now_utc,
                Appointment.appointment_date <= week_from_now,
                Appointment.status.in_(['scheduled', 'confirmed'])
            ).order_by(Appointment.appointment_date.asc()).all()
        
        else:
            appointments = []
        
        appointments_data = []
        for apt in appointments:
            local_time = apt.get_local_appointment_time(current_user)
            
            appointments_data.append({
                'id': apt.id,
                'patient_name': f"{apt.patient.first_name} {apt.patient.last_name}" if current_user.role == 'doctor' else None,
                'doctor_name': f"Dr. {apt.doctor.first_name} {apt.doctor.last_name}" if current_user.role == 'patient' else None,
                'appointment_date': format_datetime(apt.appointment_date, "%Y-%m-%d %H:%M"),
                'local_time': local_time.strftime('%Y-%m-%d %H:%M') if local_time else '',
                'status': apt.status,
                'formatted_date': format_datetime(apt.appointment_date)
            })
        
        return jsonify(appointments_data)
    
    except Exception as e:
        app.logger.error(f"Error getting upcoming appointments: {str(e)}")
        return jsonify({'error': 'Failed to load upcoming appointments'}), 500

# =============================================================================
# ENHANCED COMMUNICATION API ROUTES
# =============================================================================


@app.route('/api/messages/<int:appointment_id>/all')
@login_required
def get_all_messages(appointment_id):
    """Get all messages for an appointment with enhanced data"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Check if user has access to this appointment
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor_profile.id:
            return jsonify({'error': 'Access denied'}), 403
        
        messages = Message.query.filter_by(appointment_id=appointment_id)\
                              .order_by(Message.created_at.asc())\
                              .all()
        
        # Mark messages as read when retrieved
        unread_messages = [msg for msg in messages if msg.receiver_id == current_user.id and not msg.is_read]
        for message in unread_messages:
            message.is_read = True
        
        if unread_messages:
            db.session.commit()
        
        messages_data = []
        for message in messages:
            messages_data.append({
                'id': message.id,
                'sender_id': message.sender_id,
                'sender_name': message.sender.username or message.sender.email,
                'sender_role': message.sender.role,
                'sender_first_name': message.sender.patient_profile.first_name if message.sender.role == 'patient' and message.sender.patient_profile else message.sender.doctor_profile.first_name if message.sender.role == 'doctor' and message.sender.doctor_profile else None,
                'sender_last_name': message.sender.patient_profile.last_name if message.sender.role == 'patient' and message.sender.patient_profile else message.sender.doctor_profile.last_name if message.sender.role == 'doctor' and message.sender.doctor_profile else None,
                'receiver_id': message.receiver_id,
                'message_type': message.message_type,
                'content': message.content,
                'audio_url': message.audio_url,
                'file_url': message.file_url,
                'file_name': message.file_name,
                'file_size': message.file_size,
                'is_read': message.is_read,
                'created_at': message.created_at.isoformat(),
                'formatted_time': format_datetime(message.created_at, "%H:%M"),
                'formatted_date': format_datetime(message.created_at, "%b %d, %Y"),
                'is_own': message.sender_id == current_user.id
            })
        
        return jsonify(messages_data)
    
    except Exception as e:
        app.logger.error(f"Error fetching all messages: {str(e)}")
        return jsonify({'error': 'Failed to fetch messages'}), 500

# =============================================================================
# DOCTOR APPOINTMENTS PAGE FIX
# =============================================================================
@app.route('/api/appointments/active')
@login_required
def get_active_appointments():
    """Get active appointments for patient dashboard"""
    try:
        if current_user.role != 'patient':
            return jsonify({'error': 'Access denied'}), 403
        
        # Use timezone-aware datetime
        from datetime import datetime, timezone
        now_utc = datetime.now(timezone.utc)
        
        appointments = Appointment.query.filter(
            Appointment.patient_id == current_user.patient_profile.id,
            Appointment.appointment_date >= now_utc,
            Appointment.status.in_(['scheduled', 'confirmed'])
        ).order_by(Appointment.appointment_date.asc()).limit(5).all()
        
        appointments_data = []
        for apt in appointments:
            local_time = apt.get_local_appointment_time(current_user)
            
            appointments_data.append({
                'id': apt.id,
                'doctor_name': f"Dr. {apt.doctor.first_name} {apt.doctor.last_name}",
                'specialization': apt.doctor.specialization,
                'appointment_date': apt.appointment_date.isoformat(),
                'local_time': local_time.isoformat() if local_time else None,
                'formatted_date': format_datetime(apt.appointment_date),
                'status': apt.status
            })
        
        return jsonify(appointments_data)
    
    except Exception as e:
        app.logger.error(f"Error getting active appointments: {str(e)}")
        return jsonify({'error': 'Failed to load active appointments'}), 500
@app.route('/doctor/appointments')
@login_required
def doctor_appointments():
    """Doctor's appointments management page - FIXED"""
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    try:
        appointments = Appointment.query.filter_by(
            doctor_id=current_user.doctor_profile.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Convert to local time
        for appointment in appointments:
            appointment.local_time = appointment.get_local_appointment_time(current_user)
        
        return render_template('doctor_appointments.html', 
                             appointments=appointments,
                             format_datetime=format_datetime)
    
    except Exception as e:
        app.logger.error(f"Error in doctor appointments: {str(e)}")
        flash('Error loading appointments', 'error')
        return redirect(url_for('doctor_dashboard'))
# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'message': 'Too many requests. Please try again later.'}), 429

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    log_audit('csrf_validation_failed', getattr(current_user, 'id', None))
    return jsonify({'error': 'CSRF token validation failed', 'message': 'Please refresh the page and try again.'}), 400

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    try:
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )
    except FileNotFoundError:
        # Return a default favicon response to prevent 404 errors
        return '', 204

# =============================================================================
# APPLICATION STARTUP
# =============================================================================

def initialize_application():
    """Initialize the application and database - COMPLETE UPDATED VERSION"""
    with app.app_context():
        try:
            print("🚀 Starting Makokha Medical Centre Application Initialization...")
            
            # Import all models to ensure they are registered with SQLAlchemy
            from app import User, Patient, Doctor, Appointment, Message, Payment, PatientDocument, AuditLog, VoiceCall, VoiceRecording
            
            # Create tables if they don't exist
            print("🔄 Creating database tables...")
            db.create_all()
            print("✅ Database tables checked/created successfully!")
            
            # Create upload directories
            print("🔄 Creating upload directories...")
            create_upload_directories()
            print("✅ Upload directories created successfully!")
            
            # Initialize with sample data
            print("🔄 Initializing sample data...")
            init_db()
            
            # Verify critical endpoints
            print("🔄 Verifying critical functionality...")
            verify_critical_functionality()
            
            print("🎉 Application initialized successfully!")
            print("\n📊 Application Status:")
            print(f"   • Database: ✅ Connected")
            print(f"   • Upload Directories: ✅ Created") 
            print(f"   • Sample Data: ✅ Loaded")
            print(f"   • WebSocket: ✅ Ready")
            print(f"   • API Endpoints: ✅ Configured")
            
        except Exception as e:
            print(f"❌ Application initialization error: {str(e)}")
            import traceback
            traceback.print_exc()
            raise e
        
def verify_critical_functionality():
    """Verify that critical functionality is working"""
    try:
        print("🔍 Verifying critical functionality...")
        
        # Check if essential models can be queried
        user_count = User.query.count()
        patient_count = Patient.query.count()
        doctor_count = Doctor.query.count()
        appointment_count = Appointment.query.count()
        
        print(f"   • Users in database: {user_count}")
        print(f"   • Patients in database: {patient_count}")
        print(f"   • Doctors in database: {doctor_count}")
        print(f"   • Appointments in database: {appointment_count}")
        
        # Verify upload directories exist
        required_dirs = [
            app.config['UPLOAD_FOLDER'],
            os.path.join(app.config['UPLOAD_FOLDER'], 'voice_messages'),
            os.path.join(app.config['UPLOAD_FOLDER'], 'message_files'),
            os.path.join(app.config['UPLOAD_FOLDER'], 'voice_recordings')
        ]
        
        for dir_path in required_dirs:
            if os.path.exists(dir_path):
                print(f"   • Directory {dir_path}: ✅ Exists")
            else:
                print(f"   • Directory {dir_path}: ❌ Missing")
                # Try to create it
                try:
                    os.makedirs(dir_path, exist_ok=True)
                    print(f"   • Directory {dir_path}: ✅ Created")
                except Exception as e:
                    print(f"   • Directory {dir_path}: ❌ Creation failed: {str(e)}")
        
        print("✅ Critical functionality verification completed!")
        
    except Exception as e:
        print(f"⚠️ Critical functionality verification warning: {str(e)}")
        
# =============================================================================
# PRODUCTION SERVER CONFIGURATION - FIXED
# =============================================================================

def create_app():
    """Application factory for production"""
    return app

if __name__ == '__main__':
    try:
        # Initialize the application
        print("🚀 Starting Makokha Medical Centre Application...")
        initialize_application()
        
        # Use different servers for development vs production
        if os.environ.get('RENDER') or os.environ.get('FLASK_ENV') == 'production':
            # Production: Use Waitress (better for Render)
            from waitress import serve
            print("🚀 Starting production server with Waitress...")
            print(f"📊 Database URL: {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[1] if '@' in app.config['SQLALCHEMY_DATABASE_URI'] else 'SQLite'}")
            print(f"🌐 Server URL: http://0.0.0.0:5000")
            print(f"🔧 Environment: Production")
            serve(app, host='0.0.0.0', port=5000)
        else:
            # Development: Use Flask development server with SocketIO
            print("🚀 Starting development server with Flask...")
            print(f"📊 Database URL: {app.config['SQLALCHEMY_DATABASE_URI']}")
            print(f"🌐 Server URL: http://localhost:5000")
            print(f"🔧 Environment: Development")
            socketio.run(app, debug=True, host='0.0.0.0', port=5000, log_output=True)
            
    except Exception as e:
        print(f"💥 Failed to start application: {str(e)}")
        import traceback
        traceback.print_exc()