from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from models import db, User, ActionLog
from extensions import bcrypt
import boto3
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('buckets'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        new_user = User(email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(request.args.get('next') or url_for('buckets'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=current_user.aws_access_key,
        aws_secret_access_key=current_user.aws_secret_key
    )

@app.route('/buckets')
@login_required
def buckets():
    s3 = get_s3_client()
    try:
        buckets = s3.list_buckets()['Buckets']
    except Exception as e:
        flash("Error fetching buckets: " + str(e))
        buckets = []
    return render_template('buckets.html', buckets=buckets)

@app.route('/buckets/<bucket_name>')
@login_required
def get_objects(bucket_name):
    s3 = get_s3_client()
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name).get('Contents', [])
    except Exception as e:
        flash("Error fetching objects: " + str(e))
        objects = []
    return render_template('objects.html', objects=objects, bucket_name=bucket_name)

@app.route('/set-expiry/<bucket_name>/<path:object_key>', methods=['POST'])
@login_required
def set_expiry(bucket_name, object_key):
    s3 = get_s3_client()
    try:
        s3.put_object_tagging(
            Bucket=bucket_name,
            Key=object_key,
            Tagging={
                'TagSet': [
                    {'Key': 'expiry', 'Value': '30-days'}
                ]
            }
        )
        action = f"Set 30-day expiry for object '{object_key}' in bucket '{bucket_name}'"
        log = ActionLog(user_id=current_user.id, action=action)
        db.session.add(log)
        db.session.commit()
        flash("Expiry set successfully.")
    except Exception as e:
        flash("Failed to set expiry: " + str(e))
    return redirect(url_for('get_objects', bucket_name=bucket_name))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

