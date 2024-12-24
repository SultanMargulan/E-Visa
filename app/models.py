from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import pyotp
from sqlalchemy.orm import relationship

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)  # Increased length to 20
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

class Country(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    region = db.Column(db.String(100), nullable=False)

class CountryImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country_id = db.Column(db.Integer, db.ForeignKey('country.id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)

    # relationship with Country table
    country = db.relationship('Country', backref='images')

class VisaInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country_id = db.Column(db.Integer, db.ForeignKey('country.id'), nullable=False)
    visa_type = db.Column(db.String(100), nullable=False)
    requirements = db.Column(db.Text, nullable=False)
    processing_time = db.Column(db.String(100), nullable=False)
    cost = db.Column(db.Float, nullable=False)
    vaccinations = db.Column(db.Text)
    useful_links = db.Column(db.Text)

    # relationship with Country table
    country = relationship('Country', backref='visa_infos')

class VisaApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    country_id = db.Column(db.Integer, db.ForeignKey('country.id'), nullable=False) 
    visa_type = db.Column(db.String(50), nullable=False) 
    passport_number = db.Column(db.String(20), nullable=False) 
    documents = db.Column(db.Text, nullable=True)
    application_status = db.Column(db.String(50), nullable=False, default="Pending") 
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)

    country = db.relationship('Country', backref='visa_applications')
    user = db.relationship('User', backref='visa_applications')
