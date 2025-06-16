from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, ActionLog
from extensions import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_secret_key")
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'users.db')


db.init_app(app)

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

@app.route('/buckets')
@login_required
def buckets():
    # Placeholder
    return render_template('buckets.html')

@app.route('/credentials', methods=['GET', 'POST'])
@login_required
def credentials():
    if request.method == 'POST':
        current_user.aws_access_key = request.form['access_key']
        current_user.aws_secret_key = request.form['secret_key']
        db.session.commit()
        log = ActionLog(user_id=current_user.id, action="Updated AWS credentials")
        db.session.add(log)
        db.session.commit()
        flash("Credentials updated successfully.")
    return render_template('credentials.html')

@app.route('/logs')
@login_required
def logs():
    logs = ActionLog.query.filter_by(user_id=current_user.id).order_by(ActionLog.timestamp.desc()).all()
    return render_template('logs.html', logs=logs)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

