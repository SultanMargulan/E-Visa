import pyotp
from flask_mail import Message
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