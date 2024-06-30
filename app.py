import logging
import argparse
import os
import yaml
import smtplib
from datetime import datetime
from threading import Timer
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='app.log', filemode='w')

GREETINGS = {
    "en": "Hello",
    "es": "Hola",
    "fr": "Bonjour",
    "de": "Hallo",
    "it": "Ciao"
}

Base = declarative_base()
db = SQLAlchemy()
cache = Cache(config={'CACHE_TYPE': 'simple'})
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
scheduler = BackgroundScheduler()

class Greeting(Base):
    __tablename__ = 'greetings'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    message = Column(String)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def read_config(config_file):
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)
    return config

def greet(name, greeting="Hello"):
    if not name:
        raise ValueError("Name cannot be empty")
    
    message = f"{greeting}, {name}!"
    print(message)
    logging.info(f"Greeted {name} with message: {message}")
    
    with open("greeting.txt", "w") as file:
        file.write(message)
    
    return message

def send_email(config, message):
    smtp_server = config['smtp_server']
    smtp_port = config['smtp_port']
    sender_email = config['sender_email']
    recipient_email = config['recipient_email']
    username = config['username']
    password = config['password']

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = 'Greeting Message'
    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.close()
        logging.info(f"Email sent to {recipient_email}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

def save_to_db(session, name, message):
    greeting = Greeting(name=name, message=message)
    session.add(greeting)
    session.commit()
    logging.info(f"Saved greeting to database: {message}")

def schedule_greeting(name, greeting, schedule_time):
    now = datetime.now()
    target_time = datetime.strptime(schedule_time, "%H:%M")
    target_time = now.replace(hour=target_time.hour, minute=target_time.minute, second=0, microsecond=0)
    
    if target_time < now:
        target_time = target_time.replace(day=now.day + 1)
    
    delay = (target_time - now).total_seconds()
    Timer(delay, greet, args=[name, greeting]).start()
    logging.info(f"Scheduled greeting for {name} at {schedule_time}")

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)
cache.init_app(app)
limiter.init_app(app)
auth = HTTPBasicAuth()
socketio = SocketIO(app)
oauth = OAuth(app)
scheduler.start()

@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if verify_password(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/greet', methods=['POST'])
@auth.login_required
@cache.cached(timeout=60)
def web_greet():
    name = request.form['name']
    greeting = GREETINGS.get(request.form['greeting'], "Hello")
    message = greet(name, greeting)
    if db_enabled:
        save_to_db(db_session, name, message)
    if email_enabled:
        send_email(email_config, message)
    emit('new_greeting', {'message': message}, broadcast=True)
    return jsonify({"message": message})

@app.route('/api/greet', methods=['POST'])
@auth.login_required
@cache.cached(timeout=60)
def api_greet():
    data = request.get_json()
    name = data['name']
    greeting = GREETINGS.get(data['greeting'], "Hello")
    message = greet(name, greeting)
    if db_enabled:
        save_to_db(db_session, name, message)
    if email_enabled:
        send_email(email_config, message)
    emit('new_greeting', {'message': message}, broadcast=True)
    return jsonify({"message": message})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return 'User already exists', 400
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@socketio.on('connect')
def handle_connect():
    logging.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logging.info('Client disconnected')

# OAuth2 setup
oauth.register(
    name='google',
    client_id='YOUR_CLIENT_ID',
    client_secret='YOUR_CLIENT_SECRET',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    authorize_callback=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/auth/callback',
    client_kwargs={'scope': 'openid profile email'}
)

@app.route('/auth/login')
def auth_login():
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    session['user'] = user_info
    return redirect('/')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Greet a user by name.')
    parser.add_argument('--config', type=str, help='Path to YAML config file')
    args = parser.parse_args()

    config = read_config(args.config)
    name = config.get('name', 'World')
    greeting = GREETINGS.get(config.get('greeting'), 'Hello')

    db_enabled = config.get('db_enabled', False)
    email_enabled = config.get('email_enabled', False)

    if db_enabled:
        engine = create_engine('sqlite:///greetings.db')
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        db_session = Session()
        logging.info('Database setup complete.')

    email_config = config.get('email', {})

    schedule_time = config.get('schedule_time')
    if schedule_time:
        schedule_greeting(name, greeting, schedule_time)

    socketio.run(app)
