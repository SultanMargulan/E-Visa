import os
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, send_from_directory, current_app
from flask_login import login_user, current_user, logout_user, login_required
from app.models import User, Country, VisaApplication, VisaInfo, CountryImage
from app.forms import RegistrationForm, LoginForm, AddVisaApplicationForm
from app import db, bcrypt
from app.utils import generate_otp, send_otp_via_email, admin_required
import json
from werkzeug.utils import secure_filename
from datetime import datetime

bp = Blueprint('main', __name__)

@bp.route('/')
def home():
    popular_countries = db.session.query(Country).join(VisaApplication).group_by(Country.id).order_by(db.func.count(VisaApplication.id).desc()).limit(5).all()

    visa_types = ['Tourist', 'Work', 'Student']
    visa_count = VisaInfo.query.count()

    return render_template('home.html', popular_countries=popular_countries, visa_types=visa_types, visa_count=visa_count)

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

@bp.route('/resend-otp', methods=['GET'])
def resend_otp():
    user_id = session.get('otp_user_id')
    if not user_id:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('main.login'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('main.login'))

    otp_code = generate_otp()
    session['otp_code'] = otp_code

    try:
        send_otp_via_email(user, otp_code)
        flash("OTP has been resent to your email.", "info")
    except Exception as e:
        flash(f"Failed to send OTP: {e}", "danger")

    return redirect(url_for('main.verify_otp'))

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

    # extracting unique regions
    regions = db.session.query(Country.region).distinct().all()
    regions = [r[0] for r in regions if r[0]]

    countries = query.all()
    return render_template('countries.html', countries=countries, regions=regions)

@bp.route('/countries/<int:country_id>')
def country_detail(country_id):
    country = Country.query.get_or_404(country_id)
    visas = VisaInfo.query.filter_by(country_id=country.id).all()
    images = country.images  # Связанные изображения
    return render_template('country_detail.html', country=country, visas=visas, images=images)


# VISA APPLICATION ROUTES

@bp.route('/visa-status', methods=['GET'])
@login_required
def visa_status():
    visa_applications = VisaApplication.query.filter_by(user_id=current_user.id).order_by(VisaApplication.submitted_at.asc()).all()
    processed_applications = []

    for app in visa_applications:
        # Декодируем документы
        try:
            documents = json.loads(app.documents) if app.documents else []
        except json.JSONDecodeError:
            documents = []

        # Обрабатываем данные заявки
        processed_applications.append({
            'id': app.id,
            'status': app.application_status,
            'submitted_at': app.submitted_at,  # Передаём объект datetime
            'last_updated_at': app.last_updated_at,  # Передаём объект datetime
            'country': app.country.name if app.country else "Unknown",  # Проверяем связь с Country
            'visa_type': app.visa_type,
            'passport_number': app.passport_number,
            'documents': documents,
            'notes': app.notes or "No notes available"
        })

    return render_template('visa_status.html', applications=processed_applications)



ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@bp.route('/visa-status/add', methods=['GET', 'POST'])
@login_required
def add_visa_application():
    countries = [(country.id, country.name) for country in Country.query.all()]
    form = AddVisaApplicationForm()
    form.country_id.choices = countries

    if form.validate_on_submit():
        # Use form.documents.data instead of request.files
        file = form.documents.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_dir = current_app.config['UPLOAD_FOLDER']
            # Ensure the upload directory exists
            os.makedirs(upload_dir, exist_ok=True)
            upload_path = os.path.join(upload_dir, filename)
            
            try:
                file.save(upload_path)
            except Exception as e:
                flash(f'Error saving file: {e}', 'danger')
                return redirect(url_for('main.add_visa_application'))

            new_application = VisaApplication(
                user_id=current_user.id,
                country_id=form.country_id.data,
                visa_type=form.visa_type.data,
                passport_number=form.passport_number.data,
                documents=json.dumps([filename]),
                application_status='Pending'
            )
            db.session.add(new_application)
            db.session.commit()
            flash('Visa application submitted!', 'success')
            return redirect(url_for('main.visa_status'))
        else:
            flash('Invalid file type or no file uploaded.', 'danger')

    # Display form errors to the user
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text}: {error}", 'danger')

    return render_template('add_visa_application.html', form=form)

# ADMIN ROUTES

@bp.route('/admin', methods=['GET'])
@login_required
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    country_count = Country.query.count()
    visa_app_count = VisaApplication.query.count()
    visa_info_count = VisaInfo.query.count()

    # For statuses
    pending_count = VisaApplication.query.filter_by(application_status='Pending').count()
    approved_count = VisaApplication.query.filter_by(application_status='Approved').count()
    rejected_count = VisaApplication.query.filter_by(application_status='Rejected').count()

    return render_template(
        'admin/dashboard.html',
        user=current_user,  # Pass the current user so template can use user.username
        user_count=user_count,
        country_count=country_count,
        visa_app_count=visa_app_count,
        visa_info_count=visa_info_count,
        pending_count=pending_count,
        approved_count=approved_count,
        rejected_count=rejected_count
    )

@bp.route('/documents/<filename>')
def serve_document(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)


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


@bp.route('/admin/countries/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_country():
    if request.method == 'POST':
        name = request.form.get('name')
        region = request.form.get('region')
        image_url = request.form.get('image_url')  # Получаем URL изображения

        if name and region:
            # Создаём новую страну
            new_country = Country(name=name, region=region)
            db.session.add(new_country)
            db.session.commit()

            # Добавляем изображение, если указано
            if image_url:
                new_image = CountryImage(country_id=new_country.id, image_url=image_url)
                db.session.add(new_image)
                db.session.commit()

            flash('Country added successfully with image!', 'success')
            return redirect(url_for('main.admin_countries'))
        else:
            flash('Both name and region are required!', 'danger')

    return render_template('admin/add_country.html')

@bp.route('/admin/countries/edit/<int:country_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_country(country_id):
    country = Country.query.get_or_404(country_id)

    if request.method == 'POST':
        name = request.form.get('name')
        region = request.form.get('region')
        image_urls = request.form.get('image_urls')  # Получаем ссылки через запятую

        if name and region:
            country.name = name
            country.region = region

            # Обновляем изображения
            if image_urls:
                # Удаляем старые изображения
                CountryImage.query.filter_by(country_id=country.id).delete()

                # Добавляем новые изображения
                for url in image_urls.split(','):
                    clean_url = url.strip()
                    if clean_url:
                        new_image = CountryImage(country_id=country.id, image_url=clean_url)
                        db.session.add(new_image)

            db.session.commit()
            flash('Country updated successfully!', 'success')
            return redirect(url_for('main.admin_countries'))
        else:
            flash('Both name and region are required!', 'danger')

    # Получаем текущие ссылки на изображения
    current_image_urls = ', '.join([image.image_url for image in country.images])
    return render_template('admin/edit_country.html', country=country, image_urls=current_image_urls)



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

@bp.route('/admin/countries/<int:country_id>/add-image', methods=['GET', 'POST'])
@login_required
@admin_required
def add_country_image(country_id):
    country = Country.query.get_or_404(country_id)

    if request.method == 'POST':
        image_url = request.form.get('image_url')

        if image_url:
            new_image = CountryImage(country_id=country.id, image_url=image_url)
            db.session.add(new_image)
            db.session.commit()
            flash('Image added successfully!', 'success')
            return redirect(url_for('main.country_detail', country_id=country.id))
        else:
            flash('Image URL is required!', 'danger')

    return render_template('admin/add_country_image.html', country=country)


@bp.route('/admin/visa-applications', methods=['GET'])
@login_required
@admin_required
def admin_visa_applications():
    # Eager load related Country and User data to avoid N+1 queries
    applications = VisaApplication.query.options(
        db.joinedload(VisaApplication.country),
        db.joinedload(VisaApplication.user)
    ).all()
    
    processed_applications = []
    for app in applications:
        try:
            documents = json.loads(app.documents) if app.documents else []
        except json.JSONDecodeError:
            documents = []
        
        processed_applications.append({
            'id': app.id,
            'user': app.user,
            'country': app.country,
            'visa_type': app.visa_type,
            'passport_number': app.passport_number,
            'documents': documents,
            'submitted_at': app.submitted_at,
            'last_updated_at': app.last_updated_at,
            'status': app.application_status,
            'notes': app.notes
        })
    
    return render_template('admin/visa_applications.html', applications=processed_applications)


@bp.route('/admin/visa-applications/<int:application_id>/update', methods=['POST'])
@login_required
@admin_required
def update_visa_application_status(application_id):
    application = VisaApplication.query.get_or_404(application_id)
    new_status = request.form.get('new_status')
    notes = request.form.get('notes')  # Получаем заметки из формы

    if new_status:
        application.application_status = new_status
        application.last_updated_at = datetime.utcnow()
    
    if notes is not None:
        application.notes = notes  # Обновляем заметки

    db.session.commit()
    flash('Application updated successfully!', 'success')
    return redirect(url_for('main.admin_visa_applications'))



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

# VISA COST CALCULATOR
@bp.route('/visa-cost-calculator', methods=['GET', 'POST'])
def visa_cost_calculator():
    countries = Country.query.all()
    visa_types = ['Tourist', 'Work', 'Student']
    visa_info = None
    total_cost = None

    if request.method == 'POST':
        country_id = request.form.get('country_id')
        visa_type = request.form.get('visa_type')
        num_applicants = int(request.form.get('num_applicants', 1))

        visa_info = VisaInfo.query.filter_by(country_id=country_id, visa_type=visa_type).first()
        if visa_info:
            total_cost = visa_info.cost * num_applicants

    return render_template('visa_cost_calculator.html', countries=countries, visa_types=visa_types, visa_info=visa_info, total_cost=total_cost)

# VISA COMPARISON
@bp.route('/visa-comparison', methods=['GET', 'POST'])
def visa_comparison():
    countries = Country.query.all()
    visa_types = ['Tourist', 'Work', 'Student']
    visa_info_1 = None
    visa_info_2 = None

    if request.method == 'POST':
        country_id_1 = request.form.get('country_id_1')
        visa_type_1 = request.form.get('visa_type_1')
        country_id_2 = request.form.get('country_id_2')
        visa_type_2 = request.form.get('visa_type_2')

        visa_info_1 = VisaInfo.query.filter_by(country_id=country_id_1, visa_type=visa_type_1).first()
        visa_info_2 = VisaInfo.query.filter_by(country_id=country_id_2, visa_type=visa_type_2).first()

    return render_template('visa_comparison.html', countries=countries, visa_types=visa_types, visa_info_1=visa_info_1, visa_info_2=visa_info_2)
