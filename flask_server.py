import os
import time
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, request, redirect, flash, render_template, url_for, session, send_from_directory, jsonify, abort
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_session import Session
from zipfile import ZipFile
from sqlalchemy import delete, Column, String, LargeBinary, Integer
import shutil
import uuid
import logging
import random
import pickle
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, PasswordField, SubmitField, BooleanField, MultipleFileField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login'

def custom_serializer(data):
    """Serialize session data to a binary format."""
    try:
        return pickle.dumps(data)
    except Exception as e:
        # Handle serialization error (e.g., logging)
        return None

def custom_deserializer(data):
    """Deserialize binary session data to its original form."""
    try:
        return pickle.loads(data)
    except Exception as e:
        # Handle deserialization error (e.g., logging)
        return None

def create_app():
    app = Flask(__name__)
    
    # Basic Flask Configuration
    app.secret_key = os.environ.get('SECRET_KEY', 'optional_default_secret_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['UPLOAD_FOLDER'] = os.getenv("UPLOAD_FOLDER")
    app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 * 1024  # 500GB in bytes
    
    # Email Configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'mail.privateemail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 'yes']
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'webmaster@lockitvault.com')
    
    # Session Management Configuration
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Adjust as needed
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_SQLALCHEMY_SERIALIZER'] = custom_serializer
    app.config['SESSION_SQLALCHEMY_DESERIALIZER'] = custom_deserializer

    # Initialize Extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    csrf = CSRFProtect(app)
    session = Session(app)
    mail = Mail(app)

    # Set the login view for Flask-Login
    login_manager.login_view = 'login'
    login_manager.session_protection = 'strong'

    # Apply ProxyFix Middleware
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # Create database tables
    with app.app_context():
        db.create_all()
        
    return app

app = create_app()
mail = Mail(app)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Define Contact Form
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    attachment = FileField('Attachment', validators=[FileAllowed(['jpg', 'png', 'pdf', 'doc', 'docx', 'txt'], 'Files only!')])
    submit = SubmitField('Send Message')

def generate_secure_link(app, username, filename):
    serializer = URLSafeTimedSerializer(app.secret_key)
    token = serializer.dumps({'username': username, 'filename': filename}, salt='file-access')
    secure_link = url_for('access_secure_file', token=token, _external=True)
    return secure_link
    
def generate_secure_link_direct(username, filename):
    serializer = URLSafeTimedSerializer(app.secret_key)
    token = serializer.dumps({'username': username, 'filename': filename}, salt='file-access')
    secure_link = url_for('access_secure_file', token=token, _external=True)
    return secure_link

def generate_stars():
    static_stars = [{'top': random.uniform(0, 100), 'left': random.uniform(0, 100)} for _ in range(50)]
    twinkling_stars = [{'top': random.uniform(0, 100), 'left': random.uniform(0, 100)} for _ in range(50)]
    moving_stars = [{'top': random.uniform(0, 100), 'left': random.uniform(0, 100)} for _ in range(20)]
   
    
    return {
        'static_stars': static_stars,
        'twinkling_stars': twinkling_stars,
        'moving_stars': moving_stars,
    }

def cleanup_expired_sessions():
    """Delete expired sessions from the database."""
    with app.app_context():
        expired_sessions = Session.query.filter(Session.expiry < datetime.utcnow()).all()
        for session in expired_sessions:
            db.session.delete(session)
        db.session.commit()
        print(f"Cleaned up {len(expired_sessions)} expired sessions.")

def get_used_storage(folder_path):
    """Return the size of a folder in bytes."""
    used_storage = 0
    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isfile(item_path):
            used_storage += os.path.getsize(item_path)
        elif os.path.isdir(item_path):
            used_storage += get_used_storage(item_path)
    return used_storage

@app.cli.command("cleanup-sessions")
def cleanup_sessions_command():
    """Command to clean up expired sessions."""
    cleanup_expired_sessions()
    print("Session cleanup completed.")

def start_cleanup_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=cleanup_expired_sessions, trigger="interval", hours=24)
    scheduler.start()
    print("Scheduled session cleanup every 24 hours.")
    
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        # Process the form data and send an email
        name = form.name.data
        email = form.email.data
        subject = form.subject.data
        message = form.message.data
        attachment = form.attachment.data

        # Prepare the email message
        msg = Message(subject=subject,
                      sender=email,
                      recipients=['webmaster@lockitvault.com'],
                      body=f"Message from {name} ({email}):\n\n{message}")

        # Add attachment if provided
        if attachment:
            filename = secure_filename(attachment.filename)
            msg.attach(filename, attachment.content_type, attachment.read())

        try:
            # Send the email
            mail.send(msg)
            flash('Your message has been sent successfully!', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            logging.error(f"Failed to send email: {e}")
            flash('An error occurred while sending your message. Please try again later.', 'danger')
            
    stars_data = generate_stars()
    
    return render_template('contact.html', form=form, stars_data=stars_data)

# Route to access files using the generated secure link
@app.route('/access_secure_file/<token>')
def access_secure_file(token):
    try:
        serializer = URLSafeTimedSerializer(app.secret_key)
        data = serializer.loads(token, salt='file-access', max_age=3600)  # Token is valid for 1 hour
        
        username = data['username']
        filename = data['filename']

        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
        file_path = os.path.join(user_dir, filename)
        if not os.path.exists(file_path):
            abort(404)  # File not found

        return send_from_directory(user_dir, filename, as_attachment=False)
    
    except Exception as e:
        print(f"Failed to access file: {str(e)}")
        abort(403)  # Forbidden or token expired

class UserSession(db.Model):
    __tablename__ = 'sessions'  # Ensure this table name matches what you are using for Flask-Session
    __table_args__ = {'extend_existing': True}  # Allow modification of the existing table
    
    id = db.Column(db.String(255), primary_key=True, default=lambda: str(uuid.uuid4()))  # Generate a UUID if not provided
    session_id = db.Column(db.String(255), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)  # Use LargeBinary to store the session data
    expiry = db.Column(db.DateTime, nullable=False)
    
    @property
    def is_expired(self):
        return datetime.utcnow() > self.expiry

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)  # Store filename of profile picture
    phone = db.Column(db.String(20), nullable=True)
    name = db.Column(db.String(120), nullable=True)
    two_fa_method = db.Column(db.String(10), nullable=True)  # Changed from '2fa_method'
    language = db.Column(db.String(10), default='en')
    notifications = db.Column(db.Boolean, default=True)
    timezone = db.Column(db.String(50), default='UTC')

class SharedLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    link = db.Column(db.String(255), unique=True, nullable=False)
    
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(255), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    permanent_delete_at = db.Column(db.DateTime)

    user = db.relationship('User', backref=db.backref('files', lazy=True))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class UploadForm(FlaskForm):
    file = MultipleFileField('File')
    submit = SubmitField('Upload')

@app.route('/bin/<path:filename>')
def custom_static(filename):
    return send_from_directory('static/bin', filename)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    stars_data = generate_stars()
    return render_template('index.html', stars_data=stars_data)

@app.route('/search', methods=['GET'])
@login_required
def search_files():
    query = request.args.get('query', '').strip()
    search_results = []
    if query:
        # Query the database for files that match the search query
        search_results = File.query.filter(
            File.user_id == current_user.id,
            File.filename.ilike(f'%{query}%'),
            File.is_deleted == False
        ).all()
    
    files = [{
        'name': file.filename,
        'size': os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, file.filename)) / 1024,  # Size in KB
        'modified': file.deleted_at.strftime('%Y-%m-%d %H:%M:%S') if file.deleted_at else time.ctime(os.path.getmtime(os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, file.filename)))
    } for file in search_results]

    stars_data = generate_stars()
    return render_template('vault.html', files=files, username=current_user.username, stars_data=stars_data)

@app.route('/view_file/<username>/<filename>')
@login_required
def view_file(username, filename):
    if username is None:
        username = current_user.username
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    file_path = os.path.join(user_dir, filename)
    if os.path.exists(file_path):
        # Generate secure link and redirect to it
        secure_link = generate_secure_link(app, username, filename)
        return redirect(secure_link)  # Redirect to the secure link
    else:
        flash('File not found', 'danger')
        return redirect(url_for('vault'))

# Function to generate a shareable link
def generate_share_link(username, filename):
    serializer = URLSafeTimedSerializer(app.secret_key)
    token = serializer.dumps({'username': username, 'filename': filename}, salt='file-share')
    share_link = url_for('access_secure_file', token=token, _external=True)
    return share_link

@app.route('/generate_secure_link/<username>/<filename>', methods=['POST'])
@login_required
def generate_shareable_link(username, filename):
    if current_user.username != username:
        abort(403)  # Forbidden: User is not allowed to access this file

    # Ensure the file exists and the user has access to it
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        abort(404)  # Not found: The file does not exist

    # Generate a secure token with a limited lifetime (e.g., 1 hour)
    serializer = URLSafeTimedSerializer(app.secret_key)
    token = serializer.dumps({'username': username, 'filename': filename}, salt='file-access')

    # Create the secure link using the generated token
    secure_link = url_for('access_secure_file', token=token, _external=True)
    return jsonify({'link': secure_link})

@app.route('/send_link_via_email', methods=['POST'])
@login_required
def send_link_via_email():
    email = request.form['email']
    link = request.form['link']
    msg = Message("Your Share Link", recipients=[email])
    msg.body = f"Here is your link to access the file: {link}"
    mail.send(msg)
    return 'Email sent successfully!'

@app.route('/share_file', methods=['POST'])
@login_required
def share_file():
    filename = request.form.get('filename')
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    file_path = os.path.join(user_dir, filename)

    if os.path.exists(file_path):
        share_link = str(uuid.uuid4())
        shared_link = SharedLink(file_name=filename, username=current_user.username, link=share_link)
        db.session.add(shared_link)
        db.session.commit()
        logging.info(f"Shared file: {filename} with link: {share_link}")
        return jsonify({'link': f'{request.host_url}shared/{share_link}'})
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/shared/<link>', methods=['GET'])
@login_required
def access_shared_file(link):
    shared_link = SharedLink.query.filter_by(link=link).first()
    if shared_link:
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], shared_link.username)
        file_path = os.path.join(user_dir, shared_link.file_name)
        if os.path.exists(file_path):
            return send_from_directory(user_dir, shared_link.file_name)
    flash('Invalid or expired link', 'danger')
    return redirect(url_for('index'))

@app.before_request
def log_user_status():
    print(f"User: {current_user}, Authenticated: {current_user.is_authenticated}")

@app.before_request
def log_request_info():
    print(f"User: {current_user}, Authenticated: {current_user.is_authenticated}")

@app.route('/rename_file', methods=['POST'])
@login_required
def rename_file():
    old_filename = request.form.get('old_filename')
    new_filename = request.form.get('new_filename') + os.path.splitext(old_filename)[1]
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    old_file_path = os.path.join(user_dir, old_filename)
    new_file_path = os.path.join(user_dir, new_filename)

    if os.path.exists(old_file_path):
        os.rename(old_file_path, new_file_path)
        flash('File renamed successfully', 'success')
    else:
        flash('File not found', 'danger')
    return redirect(url_for('vault'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    print("Form submission attempt")
    form = RegistrationForm()
    if form.validate_on_submit():
        print("Form validated")
        try:
            username = form.username.data
            email = form.email.data
            password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=username, email=email, password=password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            login_user(user, remember=form.remember.data)
            return redirect(url_for('vault'))
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            flash(f'An error occurred while creating your account: {str(e)}', 'danger')
            db.session.rollback()
    else:
        if request.method == 'POST':
            flash('Please correct the errors and try again.', 'danger')

    stars_data = generate_stars()
    return render_template('register.html', form=form, stars_data=stars_data)

def generate_stars():
    static_stars = [{'top': random.uniform(0, 100), 'left': random.uniform(0, 100)} for _ in range(50)]
    twinkling_stars = [{'top': random.uniform(0, 100), 'left': random.uniform(0, 100)} for _ in range(50)]
    moving_stars = [{'top': random.uniform(0, 100), 'left': random.uniform(0, 100)} for _ in range(20)]
    
    return {
        'static_stars': static_stars,
        'twinkling_stars': twinkling_stars,
        'moving_stars': moving_stars,
    }

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Login attempt")
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print(f"Logging in with email: {email}")
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # Remember me option, adjust based on your form if available
            remember = True  # You can set this based on a form checkbox if you have one
            login_user(user, remember=form.remember.data)
            print("Login successful")
            # flash('Login successful!', 'success')
            
            # Redirect to the intended destination or default to 'vault'
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            elif user.username == 'cmann01k':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('vault'))
        else:
            print("Login unsuccessful. Please check email and password")
            flash('Login unsuccessful. Please check email and password', 'danger')
    else:
        print("Form validation failed")
        for field, errors in form.errors.items():
            for error in errors:
                print(f"Error in the {getattr(form, field).label.text}: {error}")
                flash(f"Error in the {getattr(form, field).label.text}: {error}", 'danger')

    stars_data = generate_stars()
    return render_template('login.html', form=form, stars_data=stars_data)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/restore/<filename>', methods=['POST'])
@login_required
def restore_file(filename):
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    soft_delete_dir = os.path.join(user_dir, 'soft_delete')
    file_path = os.path.join(soft_delete_dir, filename)
    
    # Check if the file exists in the soft delete folder
    if os.path.exists(file_path):
        # Update the database record
        file = db.session.query(File).filter_by(user_id=current_user.id, filename=filename.replace('.deleted', ''), is_deleted=True).first()
        if file:
            file.is_deleted = False
            file.deleted_at = None
            file.permanent_delete_at = None
            # file.filepath = new_file_path
            db.session.commit()

            # Move the file back to the main user directory
            new_file_path = os.path.join(user_dir, filename.replace('.deleted', ''))
            os.rename(file_path, new_file_path)
            # flash('File restored successfully', 'success')
            return jsonify({'message': 'File restored successfully'}), 200 
        else:
            # flash('File not found in database', 'danger')
            return jsonify({'message': 'File not found in database'}), 404
    else:
        # flash('File not found in soft delete folder', 'danger')
        return jsonify({'message': 'File not found in soft delete folder'}), 404
    
    # return redirect(url_for('vault'))

@app.route('/bulk_action', methods=['POST'])
@login_required
def bulk_action():
    action = request.form.get('action')
    selected_files = request.form.getlist('selected_files')
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    
    if action == 'download':
        # Logic to handle bulk download
        zip_filename = "bulk_download.zip"
        zip_filepath = os.path.join(user_dir, zip_filename)
        with ZipFile(zip_filepath, 'w') as zipf:
            for file in selected_files:
                zipf.write(os.path.join(user_dir, file), arcname=file)
        return send_from_directory(user_dir, zip_filename, as_attachment=True)
    
    elif action == 'delete':
        for file in selected_files:
            file_path = os.path.join(user_dir, file)
            if os.path.exists(file_path):
                os.remove(file_path)
        flash('Selected files deleted successfully', 'success')
    
    elif action == 'share':
        share_links = []
        for file in selected_files:
            file_path = os.path.join(user_dir, file)
            if os.path.exists(file_path):
                share_link = str(uuid.uuid4())
                shared_link = SharedLink(file_name=file, username=current_user.username, link=share_link)
                db.session.add(shared_link)
                share_links.append(f"{request.host_url}shared/{share_link}")
        db.session.commit()
        if share_links:
            flash(f'Files shared successfully! Shareable links: {" ".join(share_links)}', 'success')
        else:
            flash('No files to share.', 'danger')
    
    return redirect(url_for('vault'))

@app.route('/bulk_action_bin', methods=['POST'])
@login_required
def bulk_action_bin():
    # Your logic for bulk actions in the recycle bin
    action = request.form.get('action')
    selected_files = request.form.getlist('selected_deleted_files')

    if action == 'restore':
        # Logic to restore selected files
        for filename in selected_files:
            restore_file_logic(filename)
        flash('Selected files have been restored.', 'success')
    elif action == 'permanently_delete':
        # Logic to permanently delete selected files
        for filename in selected_files:
            permanently_delete_file_logic(filename)
        flash('Selected files have been permanently deleted.', 'success')
    
    return redirect(url_for('recycle'))

@app.route('/vault')
@login_required
def vault():
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    soft_delete_dir = os.path.join(user_dir, 'soft_delete')

    if not os.path.exists(user_dir):
        os.makedirs(user_dir)

    sort_by = request.args.get('sort_by', 'name')
    sort_dir = request.args.get('sort_dir', 'asc')
    files = os.listdir(user_dir)

    file_metadata = []
    for file in files:
        file_path = os.path.join(user_dir, file)
        if not os.path.isdir(file_path):  # Skip directories
            secure_link = generate_secure_link(app, current_user.username, file)
            file_info = {
                'name': file,
                'size': os.path.getsize(file_path) / 1024,  # Size in KB
                'secure_link': secure_link,
                'modified': time.ctime(os.path.getmtime(file_path))
            }
            file_metadata.append(file_info)

    reverse = sort_dir == 'desc'
    if sort_by == 'type':
        file_metadata.sort(key=lambda x: x['name'].split('.')[-1], reverse=reverse)
    elif sort_by == 'date':
        file_metadata.sort(key=lambda x: os.path.getmtime(os.path.join(user_dir, x['name'])), reverse=reverse)
    elif sort_by == 'size':
        file_metadata.sort(key=lambda x: x['size'], reverse=reverse)
    elif sort_by == 'name':
        file_metadata.sort(key=lambda x: x['name'], reverse=reverse)

    # Get list of deleted files
    deleted_files = []
    if os.path.exists(soft_delete_dir):
        for file in os.listdir(soft_delete_dir):
            file_path = os.path.join(soft_delete_dir, file)
            file_info = os.stat(file_path)
            deleted_date = datetime.fromtimestamp(file_info.st_mtime)
            permanent_deletion_date = deleted_date + timedelta(days=30)  # Adjust retention period as needed
            deleted_files.append({
                'name': file,
                'deleted_date': deleted_date.strftime('%Y-%m-%d %H:%M:%S'),
                'permanent_deletion_date': permanent_deletion_date.strftime('%Y-%m-%d %H:%M:%S')
            })

    stars_data = generate_stars()
    return render_template('vault.html', files=file_metadata, deleted_files=deleted_files, username=current_user.username, sort_by=sort_by, sort_dir=sort_dir, stars_data=stars_data)

def allowed_file(filename):
    """
    Returns True if the file's extension is not explicitly forbidden.
    This approach blocks potentially executable or harmful file types.
    """
    # List of unsafe extensions that are commonly blocked
    unsafe_extensions = {
        'exe', 'bat', 'bin', 'sh', 'js', 'jsp', 'php', 'py', 'pl', 'cgi', 'html',
        'htm', 'com', 'cmd', 'vb', 'vbs', 'vbe', 'jse', 'ws', 'wsf', 'wsc', 'wsh',
        'ps1', 'psm1', 'shb', 'scr', 'pif', 'application', 'gadget', 'msi', 'msp',
        'com', 'hta', 'cpl', 'msc', 'jar', 'apk', 'appx', 'appxbundle', 'bash',
        'bash_profile', 'bashrc', 'profile', 'bash_logout'
    }
    # extension = filename.rsplit('.', 1)[1].lower()
    # return extension not in unsafe_extensions
    if '.' in filename:
        preExtension = filename.rsplit('.', 1)
        extension = preExtension[len(preExtension) - 1].lower()
        return extension not in unsafe_extensions
    else:
        return True

@app.route('/upload', methods=['GET'])
@login_required
def display_upload_form():
    form = UploadForm()
    stars_data = generate_stars()
    return render_template('upload.html', form = form, stars_data=stars_data)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        # flash('No file part', 'danger')
        return jsonify({'message': 'No file part'}), 400
    
    files = request.files.getlist('file')
    if not files or files[0].filename == '':
        # flash('No file selected', 'danger')
        return jsonify({'message': 'No file selected'}), 404

    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    
    # check unallowed file 
    for file in files:
        if not allowed_file(file.filename):
            return jsonify({'message': f'File type not allowed: {file.filename}'}), 302
    
    # save files to UPLOAD FOLDER
    for file in files:
        print('allowed')
        filename = secure_filename(file.filename)
        file_path = os.path.join(user_dir, filename)
        file.save(file_path)

        # insert file information to database
        file_info = File()
        file_info.user_id = current_user.id
        file_info.filename = filename
        db.session.add(file_info)
        db.session.commit()
        # flash('Files uploaded successfully', 'success')
        
    return 'Files uploaded successfully', 200    
    # return redirect(url_for('vault'))

@app.route('/download/<username>/<filename>')
@login_required
def download_file(username, filename):
    if username and filename:
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
        file_path = os.path.join(user_dir, filename)
        if os.path.exists(file_path):
            return send_from_directory(user_dir, filename, as_attachment=True)
    flash('File not found', 'danger')
    return redirect(url_for('vault'))

@app.route('/delete/<username>/<filename>', methods=['POST'])
@login_required
def delete_file(username, filename):
    if username != current_user.username:
        # flash("Unauthorized access.", "danger")
        # return redirect(url_for('vault'))
        return jsonify({'message': 'Unauthorized access.'}), 404

    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    file_path = os.path.join(user_dir, filename)
    if os.path.exists(file_path):
        file = File.query.filter_by(filename=filename, user_id=current_user.id, is_deleted=False).first()
        print(file)
        if file:
            file.is_deleted = True
            file.deleted_at = datetime.utcnow()
            file.permanent_delete_at = datetime.utcnow() + timedelta(days=30)
            db.session.commit()
            recycle_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, 'soft_delete', filename)
            # os.rename(file_path, recycle_path + '.deleted')  # Optionally move it to a "deleted" location
            os.rename(file_path, recycle_path + '.deleted')
            # flash('File moved to recycle bin', 'success')
            return jsonify({'message': 'File moved to recycle bin'}), 200
        else:
            # flash('File not found in database', 'danger')
            return jsonify({'message': 'File not found in database'}), 400
    else:
        # flash('Physical file not found', 'danger')
        return jsonify({'message': 'Physical file not found'}), 400

    # return redirect(url_for('vault')) 

@app.route('/')
def index():
    stars_data = generate_stars()
    return render_template('index.html', stars_data=stars_data)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_authenticated or current_user.username != 'cmann01k':
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'delete_user_id' in request.form:
            user_id = request.form.get('delete_user_id')
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully', 'success')
            else:
                flash('User not found', 'danger')
        elif 'user_id' in request.form and 'new_password' in request.form:
            user_id = request.form.get('user_id')
            new_password = request.form.get('new_password')
            user = User.query.get(user_id)
            if user:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                flash('Password reset successfully', 'success')
            else:
                flash('User not found', 'danger')
    
    users = User.query.all()
    
    stars_data = generate_stars()
    return render_template('admin.html', users=users, stars_data=stars_data)

@app.route('/permanently_delete_file', methods=['POST'])
@login_required
def permanently_delete_file():
    filename = request.form['filename']
    # Add logic to permanently delete the file here
    flash(f'File {filename} permanently deleted!', 'success')
    return redirect(url_for('recycle'))

@app.route('/admin/user_folders/<username>')
@login_required
def view_user_folders(username):
    if not current_user.is_authenticated or current_user.username != 'cmann01k':
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('login'))
    
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    
    files = os.listdir(user_dir)
    stars_data = generate_stars()
    return render_template('vault.html', files=files, user_dir=user_dir, username=username, stars_data=stars_data)

@app.route('/recycle')
@login_required
def recycle():
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, 'soft_delete')
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)  # Ensure the directory exists

    files = os.listdir(user_dir)
    file_data = []
    
    for file in files:
        file_path = os.path.join(user_dir, file)
        if os.path.isfile(file_path):
            secure_link = generate_secure_link(app, current_user.username, file)  # Generate secure link
            deleted_file = db.session.query(File).filter(File.filename == file.replace('.deleted', '')).first()
            deleted_date = deleted_file.deleted_at
            permanently_deletion_date = deleted_file.permanent_delete_at
            file_data.append({
                'name': file,
                'size': os.path.getsize(file_path),
                'secure_link': secure_link,  # Add secure link to file data
                # 'deleted_date': time.ctime(os.path.getmtime(file_path))  # Use the last modified time as the deletion date
                'deleted_date': deleted_date,
                'permanent_deletion_date': permanently_deletion_date
            })
    stars_data = generate_stars()
    return render_template('recycle.html', deleted_files=file_data, username=current_user.username, stars_data=stars_data)

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    total_storage = 20 # in GB
    used_storage = get_used_storage(user_dir) / 1000000 # in GB
    current_user.storage_limit = total_storage
    current_user.storage_used = used_storage
    current_user.subscription__plan = 1
    stars_data = generate_stars()
    return render_template('profile.html', user=current_user, stars_data=stars_data)

@app.route('/update_profile_info', methods=['POST'])
@login_required
def update_profile_info():
    # Extract and validate data from the form
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    
    if 'profile_picture' in request.files:
        profile_picture = request.files['profile_picture']
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, filename)
            profile_picture.save(file_path)
            current_user.profile_picture = filename  # Save the filename in the database
    
    current_user.name = name
    current_user.email = email
    current_user.phone = phone
    
    try:
        db.session.commit()
        flash('Profile updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while updating your profile: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/update_security_settings', methods=['POST'])
@login_required
def update_security_settings():
    password = request.form.get('password')
    if password:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        current_user.password = hashed_password
    
    current_user.two_fa_method = request.form.get('2fa_method')
    
    try:
        db.session.commit()
        flash('Security settings updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while updating security settings: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/update_account_preferences', methods=['POST'])
@login_required
def update_account_preferences():
    current_user.language = request.form.get('language')
    current_user.notifications = 'notifications' in request.form
    current_user.timezone = request.form.get('timezone')
    
    try:
        db.session.commit()
        flash('Account preferences updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while updating account preferences: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))


@app.route('/admin/reset_password/<user_id>', methods=['GET', 'POST'])
@login_required
def reset_user_password(user_id):
    if not current_user.is_authenticated or current_user.username != 'cmann01k':
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if request.method == 'POST':
        new_password = request.form.get('password')
        if not new_password:
            flash('Password cannot be empty', 'danger')
            return redirect(url_for('reset_user_password', user_id=user_id))
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Password reset successfully', 'success')
        return redirect(url_for('admin'))
    
    stars_data = generate_stars()
    return render_template('reset_password.html', user=user, stars_data=stars_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        start_cleanup_scheduler() # Function to clean up expired sessions from the database.
    app.run(host='0.0.0.0', port=5000, debug=True)

