import os
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, current_user, logout_user, login_required
from app.models import User, Country, VisaApplication, VisaInfo
from app.forms import RegistrationForm, LoginForm, AddVisaApplicationForm
from app import db, bcrypt
from app.utils import generate_otp, send_otp_via_email
import json

bp = Blueprint('main', __name__)

@bp.route('/')
def home():
    return render_template('home.html')

# USER LOGIN AND REGISTRATION ROUTES
@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            phone_number=form.phone_number.data,
            password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.email == form.login.data) | (User.phone_number == form.login.data)
        ).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            otp_code = generate_otp()  # Генерация OTP
            session['otp_user_id'] = user.id  # Сохранение ID пользователя в сессии
            session['otp_code'] = otp_code  # Сохранение OTP в сессии
            try:
                send_otp_via_email(user, otp_code)  # Отправка OTP на email
                flash("OTP has been sent to your email.", "info")
                return redirect(url_for('main.verify_otp'))
            except Exception as e:
                flash(f"Failed to send OTP: {e}", "danger")
        else:
            flash('Login unsuccessful. Please check email/phone and password.', 'danger')
    return render_template('login.html', form=form)

@bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    user_id = session.get('otp_user_id')
    if not user_id:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('main.login'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        if otp_code == session.get('otp_code'):
            session.pop('otp_code', None)
            session.pop('otp_user_id', None)
            login_user(user)
            flash("You have been successfully logged in.", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid OTP. Please try again.", "danger")

    return render_template('verify_otp.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))

# COUNTRY ROUTES

@bp.route('/countries')
def countries():
    search = request.args.get('search')
    region = request.args.get('region')
    query = Country.query

    if search:
        query = query.filter(Country.name.ilike(f'%{search}%'))
    if region:
        query = query.filter(Country.region == region)

    countries = query.all()
    return render_template('countries.html', countries=countries)

@bp.route('/countries/<int:country_id>')
def country_detail(country_id):
    country = Country.query.get_or_404(country_id)
    visas = VisaInfo.query.filter_by(country_id=country.id).all()
    return render_template('country_detail.html', country=country, visas=visas)

# VISA APPLICATION ROUTES

@bp.route('/visa-status', methods=['GET'])
@login_required
def visa_status():
    applications = VisaApplication.query.filter_by(user_id=current_user.id).all()
    return render_template('visa_status.html', applications=applications)

@bp.route('/visa-status/add', methods=['GET', 'POST'])
@login_required
def add_visa_application():
    form = AddVisaApplicationForm()
    form.country_id.choices = [(country.id, country.name) for country in Country.query.all()]

    if form.validate_on_submit():
        file_paths = []
        if 'documents' in request.files:
            uploaded_file = request.files['documents']
            if uploaded_file.filename != '':
                file_path = os.path.join('uploads', uploaded_file.filename)
                uploaded_file.save(file_path)
                file_paths.append(file_path)

        new_application = VisaApplication(
            user_id=current_user.id,
            country_id=form.country_id.data,
            visa_type=form.visa_type.data,
            passport_number=form.passport_number.data,
            documents=json.dumps(file_paths)  # save as json
        )
        db.session.add(new_application)
        db.session.commit()
        flash('Visa application submitted successfully!', 'success')
        return redirect(url_for('main.visa_status'))

    return render_template('add_visa_application.html', form=form)

