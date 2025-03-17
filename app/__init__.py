from flask import Flask
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
from twilio.rest import Client
from dotenv import load_dotenv
import os

load_dotenv()

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    # Add to create_app() function:
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')  # Adjust path as needed
    # flask mail
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # write in .env
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # write in .env
    mail.init_app(app)

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    Migrate(app, db)

    from app.routes import bp
    app.register_blueprint(bp)

    return app

#def create_twilio_client():
#    account_sid = os.getenv('TWILIO_ACCOUNT_SID')  # Укажите в .env
#    auth_token = os.getenv('TWILIO_AUTH_TOKEN')    # Укажите в .env
#    return Client(account_sid, auth_token)