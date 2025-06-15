from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import boto3
from botocore.exceptions import ClientError
from models import db, User, ActionLog
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_s3_client():
    if current_user.is_authenticated:
        return boto3.client(
            's3',
            aws_access_key_id=current_user.aws_access_key,
            aws_secret_access_key=current_user.aws_secret_key
        )
    return boto3.client('s3')

@app.route('/')
def home():
    return redirect(url_for('list_buckets'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        aws_access = request.form['aws_access_key']
        aws_secret = request.form['aws_secret_key']
        if User.query.filter_by(email=email).first():
            return 'Email already registered.'
        user = User(email=email, password=password, aws_access_key=aws_access, aws_secret_key=aws_secret)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for('list_buckets'))
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/buckets')
@login_required
def list_buckets():
    s3 = get_s3_client()
    buckets = s3.list_buckets()
    return render_template('buckets.html', buckets=buckets['Buckets'])

@app.route('/bucket/<bucket_name>')
@login_required
def get_objects(bucket_name):
    s3 = get_s3_client()
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        objects = response.get('Contents', [])
        return render_template('objects.html', bucket_name=bucket_name, objects=objects)
    except ClientError as e:
        return f"Error fetching objects: {e}", 500

@app.route('/set-expiry/<bucket_name>/<path:object_key>', methods=['POST'])
@login_required
def set_expiry(bucket_name, object_key):
    s3 = get_s3_client()
    prefix = object_key.rsplit('/', 1)[0] + '/' if '/' in object_key else object_key
    lifecycle_config = {
        'Rules': [
            {
                'ID': f'Expire_{prefix.replace("/", "_")}',
                'Filter': {'Prefix': prefix},
                'Status': 'Enabled',
                'Expiration': {'Days': 30}
            }
        ]
    }
    try:
        s3.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
        log = ActionLog(user_id=current_user.id, action=f"Set expiry on: {object_key} in {bucket_name}")
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('get_objects', bucket_name=bucket_name))
    except ClientError as e:
        return f"Error setting lifecycle configuration: {e}", 500

if __name__ == '__main__':
    app.run(debug=True)

