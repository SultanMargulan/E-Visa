from flask import Flask
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["20/minute"],
    storage_uri="memory://"
)

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
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024   # 10 MB total per request :contentReference[oaicite:2]{index=2}

    # Initialize extensions with app
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)  # Initialize limiter with app
    CORS(app)
    Migrate(app, db)

    # Register blueprints
    from app.routes import bp
    from app.chat_routes import bp as chat_bp
    
    app.register_blueprint(bp)
    app.register_blueprint(chat_bp, url_prefix='/chat')  # Add prefix

    @app.after_request
    def add_corp(resp):
        if resp.headers.get("Content-Type", "").startswith((
            "application/javascript",
            "text/css",
            "font/",
            "audio/",
            "video/"
        )):
            resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
            resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    return app

#def create_twilio_client():
#    account_sid = os.getenv('TWILIO_ACCOUNT_SID')  # Укажите в .env
#    auth_token = os.getenv('TWILIO_AUTH_TOKEN')    # Укажите в .env
#    return Client(account_sid, auth_token)