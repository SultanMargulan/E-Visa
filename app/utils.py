import pyotp
from flask_mail import Message
from flask import abort
from flask_login import current_user
from app import mail
import os

def generate_otp():

    return pyotp.random_base32()[:6]

def send_otp_via_email(user, otp_code):

    if not user.email:
        raise ValueError("User must have a valid email address for OTP.")

    msg = Message(
        subject="Your OTP Code",
        sender=os.getenv('MAIL_USERNAME'),
        recipients=[user.email],
        body=f"Verification code: {otp_code}"
    )
    mail.send(msg)

def admin_required(func):
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)  # access forbidden
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper