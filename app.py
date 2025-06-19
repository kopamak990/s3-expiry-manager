from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from botocore.exceptions import ClientError
import os
from datetime import datetime, timedelta
import json # Added for parsing S3 bucket policies

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
    """Redirects to dashboard if logged in, otherwise shows the landing page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html', datetime=datetime)

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

# --- New Function to Check for Public Buckets ---
def check_public_buckets(s3_client):
    public_buckets = []
    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            try:
                # Check Bucket ACL
                acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl_response['Grants']:
                    # Check for 'AllUsers' or 'AuthenticatedUsers' permissions for read access
                    if 'Grantee' in grant and 'URI' in grant['Grantee']:
                        if (('http://acs.amazonaws.com/groups/global/AllUsers' == grant['Grantee']['URI'] or
                             'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' == grant['Grantee']['URI']) and
                            ('READ' == grant['Permission'] or 'FULL_CONTROL' == grant['Permission'])):
                            public_buckets.append({'name': bucket_name, 'reason': 'ACL'})
                            break # No need to check other grants for this bucket

                # Check Bucket Policy (more comprehensive for public access)
                # This needs specific permissions to read bucket policies
                try:
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy_response['Policy']) # Policy is a JSON string
                    for statement in policy_doc.get('Statement', []):
                        if (statement.get('Effect') == 'Allow' and
                            'Principal' in statement and
                            (statement['Principal'] == '*' or (isinstance(statement['Principal'], dict) and statement['Principal'].get('AWS') == '*')) and
                            'Action' in statement and
                            ((isinstance(statement['Action'], str) and ('s3:GetObject' in statement['Action'] or statement['Action'] == '*')) or
                             (isinstance(statement['Action'], list) and ('s3:GetObject' in statement['Action'] or '*' in statement['Action'])))):
                            
                            # Further check if Condition allows public access to specific resources if any
                            # For simplicity, if Principal is '*' and GetObject is allowed, we mark as public
                            public_buckets.append({'name': bucket_name, 'reason': 'Policy'})
                            break # No need to check other statements for this bucket
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        pass # No policy, not necessarily public via policy
                    else:
                        # Log other policy errors but don't stop public bucket check
                        print(f"Warning: Could not retrieve bucket policy for {bucket_name}: {e}")
                except Exception as e:
                    print(f"Warning: Error parsing bucket policy for {bucket_name}: {e}")

            except ClientError as e:
                # Common case: User doesn't have s3:GetBucketAcl or s3:GetBucketPolicy permission for ALL buckets
                if e.response['Error']['Code'] == 'AccessDenied':
                    print(f"Access Denied: Cannot check ACL/Policy for bucket {bucket_name}. Ensure 's3:GetBucketAcl' and 's3:GetBucketPolicy' permissions.")
                else:
                    print(f"Error checking bucket {bucket_name} for public access: {e}")
            except Exception as e:
                print(f"Unexpected error during public bucket check for {bucket_name}: {e}")
    except ClientError as e:
        flash(f"Error listing buckets for public check: {e}", 'error')
        print(f"Error listing buckets for public check: {e}")
    except Exception as e:
        flash(f"An unexpected error occurred during public bucket check: {e}", 'error')
        print(f"An unexpected error occurred during public bucket check: {e}")

    return public_buckets

# --- New Function to Calculate Total S3 Storage ---
def get_total_s3_storage_mb(s3_client):
    total_size_bytes = 0
    num_objects = 0
    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=bucket_name)
            
            for page in pages:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        total_size_bytes += obj['Size']
                        num_objects += 1
    except ClientError as e:
        flash(f"Error retrieving S3 storage data: {e}", 'error')
        print(f"Error retrieving S3 storage data: {e}")
        return 0, 0 # Return 0 if error
    except Exception as e:
        flash(f"An unexpected error occurred while calculating storage: {e}", 'error')
        print(f"An unexpected error occurred while calculating storage: {e}")
        return 0, 0 # Return 0 if unexpected error

    total_size_mb = total_size_bytes / (1024 * 1024)
    return total_size_mb, num_objects

# --- New Helper Function to get S3 Bucket List ---
def get_s3_bucket_names(s3_client):
    bucket_names = []
    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_names.append(bucket['Name'])
    except ClientError as e:
        flash(f"Error listing buckets for rules management: {e}", 'error')
        print(f"Error listing buckets for rules management: {e}")
    except Exception as e:
        flash(f"An unexpected error occurred while listing buckets for rules: {e}", 'error')
        print(f"An unexpected error occurred while listing buckets for rules: {e}")
    return bucket_names

# --- New Helper Function to get Lifecycle Configuration for a bucket ---
def get_bucket_lifecycle_config(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        return response.get('Rules', [])
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
            return [] # No lifecycle configuration exists for this bucket
        else:
            print(f"Error getting lifecycle config for {bucket_name}: {e}")
            flash(f"Error retrieving lifecycle rules for {bucket_name}: {e}", 'error')
            return []
    except Exception as e:
        print(f"Unexpected error getting lifecycle config for {bucket_name}: {e}")
        flash(f"An unexpected error occurred while retrieving lifecycle rules for {bucket_name}: {e}", 'error')
        return []

@app.route('/dashboard')
def dashboard():
    """Displays the user dashboard and allows AWS credential management."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    total_users = User.query.count()
    public_buckets_list = []
    total_s3_storage_mb = 0
    num_s3_objects = 0
    estimated_monthly_cost = 0

    try:
        s3 = get_s3_client()
        
        # Check for public buckets
        public_buckets_list = check_public_buckets(s3)
        if public_buckets_list:
            flash(f"WARNING: {len(public_buckets_list)} publicly accessible S3 buckets detected!", 'warning')
        
        # Get total S3 storage
        total_s3_storage_mb, num_s3_objects = get_total_s3_storage_mb(s3)
        
        # Simplified Cost Estimation: AWS S3 Standard Storage price per GB (approx, subject to region)
        # As of mid-2024, pricing is typically around $0.023/GB for first 50TB in us-east-1.
        # For simplicity, we use a fixed value. For a real SaaS, this would be region-aware and tiered.
        COST_PER_GB_PER_MONTH = 0.023 # Example: $0.023 per GB per month
        estimated_monthly_cost = (total_s3_storage_mb / 1024) * COST_PER_GB_PER_MONTH # Convert MB to GB
        
    except Exception as e:
        # Catch exception from get_s3_client if credentials are bad or other S3 errors
        print(f"Could not retrieve S3 data for dashboard due to error: {e}")
        # Flash message already handled by get_s3_client or specific check functions

    return render_template('dashboard.html', 
                           username=session['username'], 
                           datetime=datetime,
                           total_users=total_users,
                           public_buckets=public_buckets_list,
                           total_s3_storage_mb=total_s3_storage_mb,
                           num_s3_objects=num_s3_objects,
                           estimated_monthly_cost=estimated_monthly_cost)

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
                    'ID': f'expiry-object-{key.replace("/", "-")}-{datetime.now().timestamp()}', # Unique ID
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

@app.route('/rules', methods=['GET', 'POST'])
def rules():
    """Manages bucket-level lifecycle rules based on tags."""
    if 'user_id' not in session:
        flash('Please log in to manage rules.', 'warning')
        return redirect(url_for('login'))
    
    s3_client = None
    try:
        s3_client = get_s3_client()
        available_buckets = get_s3_bucket_names(s3_client)
    except Exception as e:
        flash(f"Could not load S3 client or bucket list: {e}", 'error')
        return render_template('rules.html', datetime=datetime, available_buckets=[], all_bucket_rules={})


    if request.method == 'POST':
        bucket_name = request.form.get('bucket_name')
        rule_type = request.form.get('rule_type') # 'create' or 'delete'
        rule_id_to_delete = request.form.get('rule_id_to_delete') # for delete operation

        if rule_type == 'create':
            tag_key = request.form.get('tag_key')
            tag_value = request.form.get('tag_value')
            days_to_expire = request.form.get('days_to_expire')
            prefix_filter = request.form.get('prefix_filter', '').strip() # Optional prefix

            if not all([bucket_name, tag_key, tag_value, days_to_expire]) or not days_to_expire.isdigit() or int(days_to_expire) <= 0:
                flash('Invalid input for creating a rule. Please fill all fields correctly (days must be positive integer).', 'error')
                return redirect(url_for('rules'))

            days_to_expire = int(days_to_expire)
            
            try:
                existing_rules = get_bucket_lifecycle_config(s3_client, bucket_name)
                
                # Create the new rule definition structure
                new_rule_filter = {
                    'And': {
                        'Tags': [{'Key': tag_key, 'Value': tag_value}]
                    }
                }
                if prefix_filter:
                    new_rule_filter['And']['Prefix'] = prefix_filter

                # Generate a unique ID for the new rule based on its properties
                # This makes it easier to find/update/delete the rule later
                # A more robust ID generation might hash the rule properties
                generated_id = f"s3flow-tag-expiry-{bucket_name}-{tag_key}-{tag_value}-{days_to_expire}"
                if prefix_filter:
                    generated_id += f"-prefix-{prefix_filter.replace('/', '-')}"
                generated_id = generated_id.replace('.', '_').replace(':', '_').replace(' ', '_').lower()[:128] # Sanitize for S3 ID length

                new_rule = {
                    'ID': generated_id,
                    'Filter': new_rule_filter,
                    'Status': 'Enabled',
                    'Expiration': {'Days': days_to_expire}
                }

                # Check if a similar rule (same bucket, same tags, same prefix) already exists.
                # If so, update it. Otherwise, add as new.
                found_and_updated = False
                for i, rule in enumerate(existing_rules):
                    if rule.get('Filter') == new_rule_filter: # Simple equality check for filter
                        existing_rules[i] = new_rule # Replace the old rule with the updated one
                        found_and_updated = True
                        break
                
                if not found_and_updated:
                    existing_rules.append(new_rule)
                
                lifecycle_config_payload = {'Rules': existing_rules}
                s3_client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle_config_payload)
                log_action(session['user_id'], f"Created/Updated lifecycle rule on {bucket_name} for tag {tag_key}:{tag_value} to expire in {days_to_expire} days.")
                flash(f"Lifecycle rule successfully set for '{bucket_name}'.", 'success')
            except ClientError as e:
                flash(f"Error creating/updating rule: {e}", 'error')
                print(f"Error creating/updating rule: {e}")
            except Exception as e:
                flash(f"An unexpected error occurred: {e}", 'error')
                print(f"An unexpected error occurred: {e}")
            
        elif rule_type == 'delete':
            if not all([bucket_name, rule_id_to_delete]):
                flash('Invalid input for deleting a rule.', 'error')
                return redirect(url_for('rules'))

            try:
                existing_rules = get_bucket_lifecycle_config(s3_client, bucket_name)
                # Filter out the rule to be deleted
                updated_rules = [rule for rule in existing_rules if rule.get('ID') != rule_id_to_delete]

                if len(updated_rules) == 0:
                    # If no rules left, delete the entire configuration
                    s3_client.delete_bucket_lifecycle_configuration(Bucket=bucket_name)
                    log_action(session['user_id'], f"Deleted all lifecycle rules from {bucket_name}.")
                else:
                    # Otherwise, put the updated list of rules
                    lifecycle_config_payload = {'Rules': updated_rules}
                    s3_client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle_config_payload)
                    log_action(session['user_id'], f"Deleted lifecycle rule '{rule_id_to_delete}' from {bucket_name}.")
                flash(f"Lifecycle rule '{rule_id_to_delete}' removed successfully from '{bucket_name}'.", 'success')
            except ClientError as e:
                flash(f"Error deleting rule: {e}", 'error')
                print(f"Error deleting rule: {e}")
            except Exception as e:
                flash(f"An unexpected error occurred: {e}", 'error')
                print(f"An unexpected error occurred: {e}")

        return redirect(url_for('rules'))
    
    # GET request: Display existing rules
    all_bucket_rules = {}
    for bucket_name in available_buckets:
        rules_for_bucket = get_bucket_lifecycle_config(s3_client, bucket_name)
        if rules_for_bucket:
            all_bucket_rules[bucket_name] = rules_for_bucket

    return render_template('rules.html', 
                           datetime=datetime, 
                           available_buckets=available_buckets,
                           all_bucket_rules=all_bucket_rules)

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
