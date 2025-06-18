from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
import os
from datetime import datetime, timedelta

# Required for URL quoting (e.g., for object keys with special characters)
from urllib.parse import quote

# Import Fernet for symmetric encryption of sensitive data
from cryptography.fernet import Fernet

# --- Application Initialization and Configuration ---
app = Flask(__name__)

# Load FLASK_SECRET_KEY from environment variable for secure session management.
# This is CRUCIAL for production. A warning is printed if it's not set locally.
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
if not app.secret_key:
    # This is a fallback for local development only. DO NOT rely on this in production.
    app.secret_key = 'a_very_insecure_default_secret_key_for_dev_ONLY_change_me_in_prod'
    print("WARNING: FLASK_SECRET_KEY environment variable not set. Using a default for development.")
    print("For production, set a strong, random FLASK_SECRET_KEY environment variable.")


# Load FERNET_KEY from environment variable. This key is used to encrypt AWS secret keys.
# It MUST be a 32-URL-safe-base64-encoded-byte key. Generate it once and store securely.
FERNET_KEY = os.environ.get('FERNET_KEY')
if not FERNET_KEY:
    # This generates a temporary key for local development. Data encrypted with this
    # key will NOT be recoverable if the application restarts and the key changes.
    print("WARNING: FERNET_KEY environment variable not set. Generating a temporary key for development.")
    temp_key = Fernet.generate_key()
    FERNET_KEY = temp_key.decode() # Fernet key needs to be bytes, but we store it as string in env var
    print(f"Temporary FERNET_KEY: {FERNET_KEY}")
    print("For production, generate a FERNET_KEY once (Fernet.generate_key().decode())")
    print("and set it as a persistent environment variable (FERNET_KEY).")

# Initialize Fernet cipher suite using the loaded FERNET_KEY
try:
    cipher_suite = Fernet(FERNET_KEY.encode()) # Fernet expects a bytes key
except Exception as e:
    print(f"ERROR: Could not initialize Fernet cipher. Check your FERNET_KEY format/value. Error: {e}")
    cipher_suite = None # If initialization fails, encryption/decryption functions will raise errors


# Database Configuration: Using an absolute path for robustness.
base_dir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(base_dir, 'instance')
os.makedirs(instance_path, exist_ok=True) # Ensure 'instance' directory exists
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "app.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable tracking modifications overhead
db = SQLAlchemy(app)

# --- Database Models ---

# User model: Stores user credentials and encrypted AWS credentials.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # Stores hashed password
    aws_access_key = db.Column(db.String(128)) # AWS Access Key ID, less sensitive, stored as is
    encrypted_aws_secret_key = db.Column(db.Text) # Encrypted AWS Secret Access Key, stored securely

    def __repr__(self):
        return f'<User {self.username}>'

# ActionLog model: Records user actions for auditing.
class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # Automatically records creation time

    def __repr__(self):
        return f'<ActionLog {self.user_id} - {self.action} at {self.timestamp}>'

# --- Utility Functions for Encryption/Decryption ---

# Encrypts plaintext data using the configured Fernet cipher suite.
def encrypt_secret(secret_data):
    if not cipher_suite:
        raise ValueError("Encryption cipher not initialized. Cannot encrypt data. Check FERNET_KEY.")
    # Fernet operates on bytes, so encode string to bytes before encryption
    return cipher_suite.encrypt(secret_data.encode('utf-8')).decode('utf-8')

# Decrypts encrypted data using the configured Fernet cipher suite.
def decrypt_secret(encrypted_data):
    if not cipher_suite:
        raise ValueError("Encryption cipher not initialized. Cannot decrypt data. Check FERNET_KEY.")
    # Fernet operates on bytes, so encode string to bytes before decryption
    return cipher_suite.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

# Helper function to log user actions to the database.
def log_action(user_id, action):
    new_log = ActionLog(user_id=user_id, action=action)
    db.session.add(new_log)
    db.session.commit()

# --- Flask Routes ---

@app.route('/')
def home():
    """Redirects to dashboard if logged in, otherwise to login page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html')

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first() 

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password. Please try again.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs out the current user by clearing the session."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    """Displays the user dashboard and allows AWS credential management."""
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    
    # --- New Feature: Display Total Users ---
    total_users = User.query.count()

    # Pass datetime object to template for copyright year
    return render_template('dashboard.html', 
                           username=session['username'], 
                           datetime=datetime,
                           total_users=total_users)

@app.route('/credentials', methods=['POST'])
def credentials():
    """Handles updating and encrypting AWS credentials for the logged-in user."""
    if 'user_id' not in session:
        flash('Please log in to update credentials.', 'warning')
        return redirect(url_for('login'))

    access_key = request.form['access_key']
    secret_key = request.form['secret_key'] # Raw secret key from form
    user = User.query.get(session['user_id'])
    
    try:
        # Encrypt the sensitive secret key before storing it in the database
        encrypted_secret_key = encrypt_secret(secret_key)
        user.aws_access_key = access_key
        user.encrypted_aws_secret_key = encrypted_secret_key # Store the encrypted string
        db.session.commit()
        log_action(session['user_id'], "Updated AWS credentials (secret key encrypted)")
        flash('AWS credentials updated successfully.', 'success')
    except ValueError as ve:
        # Catch errors if Fernet key is not initialized correctly
        flash(f'Security configuration error: {ve}. Please contact support.', 'error')
        print(f"Error encrypting secret key: {ve}") # Log for debugging
    except Exception as e:
        flash(f'Error updating credentials: {e}', 'error')
        print(f"Error updating credentials in DB: {e}") # Log for debugging
    return redirect(url_for('dashboard'))

def get_s3_client():
    """
    Helper function to get an S3 client for the logged-in user.
    Decrypts the AWS Secret Access Key before use.
    """
    user = User.query.get(session['user_id'])
    if not user or not user.aws_access_key or not user.encrypted_aws_secret_key:
        flash('AWS credentials not found. Please update them in your dashboard.', 'error')
        # Raise an exception to be caught by calling routes for proper error handling
        raise Exception("AWS credentials missing for user or not securely configured.") 

    try:
        # Decrypt the stored secret key before creating the boto3 client
        decrypted_secret_key = decrypt_secret(user.encrypted_aws_secret_key)
        return boto3.client(
            's3',
            aws_access_key_id=user.aws_access_key,
            aws_secret_access_key=decrypted_secret_key
        )
    except ValueError as ve:
        # Catch errors if Fernet key is not initialized or decryption fails
        flash(f'Security configuration error: {ve}. Cannot decrypt AWS secret key.', 'error')
        print(f"Error decrypting AWS secret key: {ve}") # Log for debugging
        raise Exception(f"Failed to decrypt AWS secret key: {ve}")
    except Exception as e:
        flash(f'Error initializing S3 client: {e}', 'error')
        print(f"Error initializing S3 client with decrypted key: {e}") # Log for debugging
        raise Exception(f"S3 client initialization failed: {e}")

@app.route('/buckets')
def buckets():
    """Lists all S3 buckets for the configured AWS account."""
    if 'user_id' not in session:
        flash('Please log in to view buckets.', 'warning')
        return redirect(url_for('login'))
    try:
        s3 = get_s3_client()
        response = s3.list_buckets()
        buckets_list = response['Buckets']
        flash('Successfully loaded S3 buckets.', 'success')
        # Ensure datetime is passed to the template
        return render_template('buckets.html', buckets=buckets_list, datetime=datetime)
    except Exception as e:
        flash(f'Error listing buckets: {e}', 'error')
        # Ensure datetime is passed even in error case to prevent template rendering issues
        return render_template('dashboard.html', username=session['username'], datetime=datetime) # Redirect back to dashboard on error

@app.route('/buckets/<bucket_name>')
def bucket_objects(bucket_name):
    """Lists objects within a specific S3 bucket."""
    if 'user_id' not in session:
        flash('Please log in to view bucket contents.', 'warning')
        return redirect(url_for('login'))
    try:
        s3 = get_s3_client()
        response = s3.list_objects_v2(Bucket=bucket_name)
        objects = response.get('Contents', [])
        # Ensure object keys are properly quoted for URLs (handles special characters)
        for obj in objects:
            obj['Key_quoted'] = quote(obj['Key'], safe='') 
        flash(f'Successfully loaded objects for bucket: {bucket_name}.', 'success')
        # Ensure datetime is passed to the template
        return render_template('bucket_objects.html', bucket=bucket_name, objects=objects, datetime=datetime)
    except Exception as e:
        flash(f'Error listing objects in bucket {bucket_name}: {e}', 'error')
        # Ensure datetime is passed even in error case to prevent template rendering issues
        # Provide an empty list for objects to prevent Jinja2 errors if they are iterated
        return render_template('buckets.html', buckets=[], datetime=datetime) # Redirect back to buckets list on error

@app.route('/download/<bucket>/<path:key>')
def download_object(bucket, key):
    """Generates a presigned URL for downloading an S3 object."""
    if 'user_id' not in session:
        flash('Please log in to download objects.', 'warning')
        return redirect(url_for('login'))
    try:
        s3 = get_s3_client()
        url = s3.generate_presigned_url('get_object',
                                         Params={'Bucket': bucket, 'Key': key},
                                         ExpiresIn=3600) # URL valid for 1 hour (3600 seconds)
        log_action(session['user_id'], f"Downloaded: {key} from {bucket}")
        flash(f"Generated download link for {key}.", 'info')
        return redirect(url)
    except Exception as e:
        flash(f'Error generating download link for {key}: {e}', 'error')
        return redirect(url_for('bucket_objects', bucket_name=bucket))

@app.route('/delete/<bucket>/<path:key>', methods=['POST'])
def delete_object(bucket, key):
    """Deletes an S3 object from a bucket."""
    if 'user_id' not in session:
        flash('Please log in to delete objects.', 'warning')
        return redirect(url_for('login'))
    try:
        s3 = get_s3_client()
        s3.delete_object(Bucket=bucket, Key=key)
        log_action(session['user_id'], f"Deleted: {key} from {bucket}")
        flash(f"Object '{key}' deleted successfully from '{bucket}'.", 'success')
    except Exception as e:
        flash(f'Error deleting object {key}: {e}', 'error')
    return redirect(url_for('bucket_objects', bucket_name=bucket))

@app.route('/expiry/<bucket>/<path:key>', methods=['POST'])
def set_expiry(bucket, key):
    """Sets a lifecycle rule to expire an S3 object after a specified number of days, or removes it."""
    if 'user_id' not in session:
        flash('Please log in to set expiry.', 'warning')
        return redirect(url_for('login'))
    try:
        days_str = request.form['days']

        s3 = get_s3_client()
        
        # Get existing lifecycle rules to avoid overwriting them.
        existing_rules = []
        try:
            response = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
            existing_rules = response.get('Rules', [])
        except s3.exceptions.NoSuchLifecycleConfiguration:
            pass # No existing rules, start with an empty list
        except Exception as e:
            print(f"Warning: Could not retrieve existing lifecycle configuration for '{bucket}': {e}")

        # Filter out any existing rule that might conflict with the new prefix (the object itself).
        updated_rules = [rule for rule in existing_rules if rule.get('Prefix') != key]

        if days_str == 'never': # Special value to remove expiry
            if len(updated_rules) == 0:
                # If no other rules exist after removing, delete the entire configuration
                s3.delete_bucket_lifecycle_configuration(Bucket=bucket)
                log_action(session['user_id'], f"Removed all expiry rules from {bucket}")
                flash(f"Expiry rule removed for object '{key}' in bucket '{bucket}'.", 'success')
            else:
                # If other rules exist, just update with the filtered list
                lifecycle_config_payload = {'Rules': updated_rules}
                s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=lifecycle_config_payload)
                log_action(session['user_id'], f"Removed expiry rule for {key} in {bucket}")
                flash(f"Expiry rule removed for object '{key}' in bucket '{bucket}'.", 'success')
        else:
            try:
                days = int(days_str)
                if days <= 0:
                    flash('Days must be a positive integer to set expiry.', 'error')
                    return redirect(url_for('bucket_objects', bucket_name=bucket))

                expiration_date = (datetime.utcnow() + timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S.000Z')

                new_rule = {
                    'ID': f'expire-{key.replace("/", "-")}-{datetime.now().timestamp()}', # Unique ID
                    'Prefix': key,
                    'Status': 'Enabled',
                    'Expiration': {'Date': expiration_date}
                }
                updated_rules.append(new_rule)
                
                lifecycle_config_payload = {'Rules': updated_rules}
                s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=lifecycle_config_payload)
                
                log_action(session['user_id'], f"Set expiry for {key} in {bucket} after {days} days")
                flash(f"Expiry set for object '{key}' after {days} days in bucket '{bucket}'.", 'success')
            except ValueError:
                flash('Invalid number of days. Please enter a positive integer or select "Never Expire".', 'error')
    except Exception as e:
        flash(f'Error setting/removing expiry for {key}: {e}', 'error')
        print(f"Error setting/removing expiry: {e}") # Log for debugging
    return redirect(url_for('bucket_objects', bucket_name=bucket))

@app.route('/logs')
def view_logs():
    """Displays the action log for the current user."""
    if 'user_id' not in session:
        flash('Please log in to view action logs.', 'warning')
        return redirect(url_for('login'))
    # Retrieve logs for the current user, ordered by most recent timestamp
    logs = ActionLog.query.filter_by(user_id=session['user_id']).order_by(ActionLog.timestamp.desc()).all()
    flash('Successfully loaded action logs.', 'success')
    # Pass datetime object to template for displaying timestamps consistently
    return render_template('action_log.html', logs=logs, datetime=datetime)

# --- Application Entry Point ---
if __name__ == "__main__":
    with app.app_context():
        # Creates database tables defined in models if they do not already exist.
        # This is safe to call on every startup in development.
        db.create_all()
    # Run the Flask development server.
    # For production, NEVER use debug=True. Use a WSGI server like Gunicorn/uWSGI.
    app.run(debug=False) # Production-ready: debug=False
