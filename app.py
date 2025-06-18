from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
import os
from datetime import datetime, timedelta # Ensure datetime is imported

app = Flask(__name__)
app.secret_key = 'your_secret_key_here' # Consider using an environment variable for production

# --- IMPORTANT: Using an absolute path for the database ---
# Ensure instance folder exists, and build an absolute path for the database file
base_dir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(base_dir, 'instance')
os.makedirs(instance_path, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "app.db")}'
# ----------------------------------------------------------

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model for storing user information, including AWS credentials
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    aws_access_key = db.Column(db.String(128))
    aws_secret_key = db.Column(db.String(128))

    def __repr__(self):
        return f'<User {self.username}>'

# ActionLog model for logging user activities
class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ActionLog {self.user_id} - {self.action} at {self.timestamp}>'

# Helper function to log user actions
def log_action(user_id, action):
    new_log = ActionLog(user_id=user_id, action=action)
    db.session.add(new_log)
    db.session.commit()

@app.route('/')
def home():
    # Redirect to dashboard if user is already logged in, otherwise to login page
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username already exists
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
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    # Ensure user is logged in to access dashboard
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    # Pass the datetime object to the template context
    return render_template('dashboard.html', username=session['username'], datetime=datetime)

@app.route('/credentials', methods=['POST'])
def credentials():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash('Please log in to update credentials.', 'warning')
        return redirect(url_for('login'))

    access_key = request.form['access_key']
    secret_key = request.form['secret_key']
    user = User.query.get(session['user_id'])
    
    # Update user's AWS credentials
    user.aws_access_key = access_key
    user.aws_secret_key = secret_key
    db.session.commit()
    log_action(session['user_id'], "Updated AWS credentials")
    flash('AWS credentials updated successfully.', 'success')
    return redirect(url_for('dashboard'))

# Helper function to get an S3 client for the logged-in user
def get_s3_client():
    user = User.query.get(session['user_id'])
    if not user or not user.aws_access_key or not user.aws_secret_key:
        flash('AWS credentials not found. Please update them in your dashboard.', 'error')
        # This will raise an exception if credentials are truly missing, caught in calling routes
        raise Exception("AWS credentials missing for user.") 
    return boto3.client(
        's3',
        aws_access_key_id=user.aws_access_key,
        aws_secret_access_key=user.aws_secret_key
    )

@app.route('/buckets')
def buckets():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash('Please log in to view buckets.', 'warning')
        return redirect(url_for('login'))
    try:
        s3 = get_s3_client()
        response = s3.list_buckets()
        buckets_list = response['Buckets']
        flash('Successfully loaded S3 buckets.', 'success')
        return render_template('buckets.html', buckets=buckets_list)
    except Exception as e:
        flash(f'Error listing buckets: {e}', 'error')
        return redirect(url_for('dashboard')) # Redirect back to dashboard on error

@app.route('/buckets/<bucket_name>')
def bucket_objects(bucket_name):
    # Ensure user is logged in
    if 'user_id' not in session:
        flash('Please log in to view bucket contents.', 'warning')
        return redirect(url_for('login'))
    try:
        s3 = get_s3_client()
        response = s3.list_objects_v2(Bucket=bucket_name)
        objects = response.get('Contents', [])
        # Ensure object keys are properly quoted for URLs
        for obj in objects:
            obj['Key_quoted'] = quote(obj['Key'], safe='') 
        flash(f'Successfully loaded objects for bucket: {bucket_name}.', 'success')
        return render_template('bucket_objects.html', bucket=bucket_name, objects=objects)
    except Exception as e:
        flash(f'Error listing objects in bucket {bucket_name}: {e}', 'error')
        return redirect(url_for('buckets')) # Redirect back to buckets list on error

@app.route('/download/<bucket>/<path:key>')
def download_object(bucket, key):
    # Ensure user is logged in
    if 'user_id' not in session:
        flash('Please log in to download objects.', 'warning')
        return redirect(url_for('login'))
    try:
        s3 = get_s3_client()
        url = s3.generate_presigned_url('get_object',
                                         Params={'Bucket': bucket, 'Key': key},
                                         ExpiresIn=3600) # URL valid for 1 hour
        log_action(session['user_id'], f"Downloaded: {key} from {bucket}")
        flash(f"Generated download link for {key}.", 'info')
        return redirect(url)
    except Exception as e:
        flash(f'Error generating download link for {key}: {e}', 'error')
        return redirect(url_for('bucket_objects', bucket_name=bucket))

@app.route('/delete/<bucket>/<path:key>', methods=['POST'])
def delete_object(bucket, key):
    # Ensure user is logged in
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
    # Ensure user is logged in
    if 'user_id' not in session:
        flash('Please log in to set expiry.', 'warning')
        return redirect(url_for('login'))
    try:
        days = int(request.form['days'])
        if days <= 0:
            flash('Days must be a positive integer.', 'error')
            return redirect(url_for('bucket_objects', bucket_name=bucket))

        # Calculate expiration date in UTC
        expiration_date = (datetime.utcnow() + timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S.000Z')

        s3 = get_s3_client()
        
        lifecycle_config = {
            'Rules': [{
                'ID': f'expire-{key.replace("/", "-")}-{datetime.now().timestamp()}', # Unique ID
                'Prefix': key,
                'Status': 'Enabled',
                'Expiration': {'Date': expiration_date}
            }]
        }
        # Get existing lifecycle rules to avoid overwriting all of them
        try:
            existing_lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
            rules = existing_lifecycle.get('Rules', [])
            # Remove any existing rule for this prefix before adding a new one
            rules = [rule for rule in rules if rule.get('Prefix') != key]
            rules.append(lifecycle_config['Rules'][0])
            lifecycle_config['Rules'] = rules
        except s3.exceptions.NoSuchLifecycleConfiguration:
            pass # No existing rules, so we just use the new one
        except Exception as e:
            # Log this error but don't stop execution, as it might just mean no config exists
            print(f"Warning: Could not retrieve existing lifecycle configuration: {e}")


        s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=lifecycle_config)
        log_action(session['user_id'], f"Set expiry for {key} in {bucket} after {days} days")
        flash(f"Expiry set for object '{key}' after {days} days in bucket '{bucket}'.", 'success')
    except ValueError:
        flash('Invalid number of days. Please enter an integer.', 'error')
    except Exception as e:
        flash(f'Error setting expiry for {key}: {e}', 'error')
    return redirect(url_for('bucket_objects', bucket_name=bucket))

@app.route('/logs')
def view_logs():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash('Please log in to view action logs.', 'warning')
        return redirect(url_for('login'))
    # Retrieve logs for the current user, ordered by most recent
    logs = ActionLog.query.filter_by(user_id=session['user_id']).order_by(ActionLog.timestamp.desc()).all()
    # Pass the datetime object to the template context
    return render_template('action_log.html', logs=logs, datetime=datetime)

# Initialize the database within the application context
if __name__ == "__main__":
    with app.app_context():
        db.create_all() # Creates tables if they don't exist
    app.run(debug=True) # Run the Flask development server in debug mode
