from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from app.models import User
from wtforms.validators import Regexp

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField(
        'Phone Number',
        validators=[
            DataRequired(),
            Regexp(r'^\+7 \(\d{3}\) \d{3} \d{2}-\d{2}$', message="Phone number must be in the format +7 (XXX) XXX XX-XX")
        ]
    )
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already taken. Please use a different one.')

    def validate_phone_number(self, phone_number):
        user = User.query.filter_by(phone_number=phone_number.data).first()
        if user:
            raise ValidationError('Phone number is already taken. Please use a different one.')

class LoginForm(FlaskForm):
    login = StringField('Email or Phone Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
class AddVisaApplicationForm(FlaskForm):
    country_id = SelectField('Country', coerce=int, validators=[DataRequired()])
    visa_type = SelectField('Visa Type', choices=[('Tourist', 'Tourist'), ('Work', 'Work'), ('Student', 'Student')], validators=[DataRequired()])
    passport_number = StringField(
        'Passport Number',
        validators=[
            DataRequired(),
            Regexp(r'^[A-Z]\d{7}$', message="Passport number must be in the format: A1234567")
        ]
    )
    submit = SubmitField('Submit')
