import os
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, current_user, logout_user, login_required
from app.models import User, Country, VisaApplication, VisaInfo
from app.forms import RegistrationForm, LoginForm, AddVisaApplicationForm
from app import db, bcrypt
from app.utils import generate_otp, send_otp_via_email, admin_required
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

# ADMIN ROUTES

@bp.route('/admin', methods=['GET'])
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

# CRUD для пользователей
@bp.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@bp.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('main.admin_users'))

# CRUD for countries

# Showing all countries
@bp.route('/admin/countries', methods=['GET'])
@login_required
@admin_required
def admin_countries():
    countries = Country.query.all()
    return render_template('admin/countries.html', countries=countries)

# Adding a new country
@bp.route('/admin/countries/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_country():
    if request.method == 'POST':
        name = request.form.get('name')
        region = request.form.get('region')

        if name and region:
            new_country = Country(name=name, region=region)
            db.session.add(new_country)
            db.session.commit()
            flash('Country added successfully!', 'success')
            return redirect(url_for('main.admin_countries'))
        else:
            flash('Both name and region are required!', 'danger')

    return render_template('admin/add_country.html')

# Editing a country
@bp.route('/admin/countries/edit/<int:country_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_country(country_id):
    country = Country.query.get_or_404(country_id)

    if request.method == 'POST':
        country.name = request.form.get('name')
        country.region = request.form.get('region')

        if country.name and country.region:
            db.session.commit()
            flash('Country updated successfully!', 'success')
            return redirect(url_for('main.admin_countries'))
        else:
            flash('Both name and region are required!', 'danger')

    return render_template('admin/edit_country.html', country=country)

# Deleting a country
@bp.route('/admin/countries/delete/<int:country_id>', methods=['POST'])
@login_required
@admin_required
def delete_country(country_id):
    country = Country.query.get_or_404(country_id)
    db.session.delete(country)
    db.session.commit()
    flash('Country deleted successfully!', 'success')
    return redirect(url_for('main.admin_countries'))

# CRUD для заявок на визу
@bp.route('/admin/visa-applications', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_visa_applications():
    applications = VisaApplication.query.all()
    if request.method == 'POST':
        application_id = request.form.get('application_id')
        new_status = request.form.get('new_status')
        application = VisaApplication.query.get(application_id)
        if application:
            application.application_status = new_status
            db.session.commit()
            flash('Application status updated', 'success')
        return redirect(url_for('main.admin_visa_applications'))
    return render_template('admin/visa_applications.html', applications=applications)

# VISA INFO ROUTES FOR ADMIN
@bp.route('/admin/visa-info', methods=['GET'])
@login_required
@admin_required
def admin_visa_info():
    visa_info_list = VisaInfo.query.all()
    return render_template('admin/visa_info.html', visa_info_list=visa_info_list)

@bp.route('/admin/visa-info/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_visa_info():
    if request.method == 'POST':
        country_id = request.form.get('country_id')
        visa_type = request.form.get('visa_type')
        requirements = request.form.get('requirements')
        processing_time = request.form.get('processing_time')
        cost = request.form.get('cost')
        vaccinations = request.form.get('vaccinations')
        useful_links = request.form.get('useful_links')

        new_visa_info = VisaInfo(
            country_id=country_id,
            visa_type=visa_type,
            requirements=requirements,
            processing_time=processing_time,
            cost=cost,
            vaccinations=vaccinations,
            useful_links=useful_links
        )
        db.session.add(new_visa_info)
        db.session.commit()
        flash('Visa information added successfully', 'success')
        return redirect(url_for('main.admin_visa_info'))
    countries = Country.query.all()
    return render_template('admin/add_visa_info.html', countries=countries)

@bp.route('/admin/visa-info/edit/<int:visa_info_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_visa_info(visa_info_id):
    visa_info = VisaInfo.query.get_or_404(visa_info_id)
    if request.method == 'POST':
        visa_info.country_id = request.form.get('country_id')
        visa_info.visa_type = request.form.get('visa_type')
        visa_info.requirements = request.form.get('requirements')
        visa_info.processing_time = request.form.get('processing_time')
        visa_info.cost = request.form.get('cost')
        visa_info.vaccinations = request.form.get('vaccinations')
        visa_info.useful_links = request.form.get('useful_links')

        db.session.commit()
        flash('Visa information updated successfully', 'success')
        return redirect(url_for('main.admin_visa_info'))

    countries = Country.query.all()
    return render_template('admin/edit_visa_info.html', visa_info=visa_info, countries=countries)

@bp.route('/admin/visa-info/delete/<int:visa_info_id>', methods=['POST'])
@login_required
@admin_required
def delete_visa_info(visa_info_id):
    visa_info = VisaInfo.query.get_or_404(visa_info_id)
    db.session.delete(visa_info)
    db.session.commit()
    flash('Visa information deleted successfully', 'success')
    return redirect(url_for('main.admin_visa_info'))
