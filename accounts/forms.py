from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms import ValidationError
import re
from wtforms.validators import DataRequired, EqualTo, Email, Regexp
from flask_wtf.recaptcha import RecaptchaField


def password_policy(form, field):
    password = field.data
    messages = []

    if len(password) < 8 or len(password) > 15:
        messages.append("Password must be between 8 and 15 characters long.")
    if not re.search(r'[A-Z]', password):
        messages.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        messages.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        messages.append("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        messages.append("Password must contain at least one special character.")

    if messages:
        for message in messages:
            flash(message, category='danger')  # Flash each message
        raise ValidationError("Password does not meet complexity requirements.")

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), password_policy])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password',
                                                                                                 message='Passwords do not match!')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    #captcha = RecaptchaField()
    pin = PasswordField('Pin', validators=[DataRequired()])
    submit = SubmitField('Login')


class MFASetupForm(FlaskForm):
    verification_code = StringField('Enter 6-digit code', validators=[DataRequired()])
    submit = SubmitField("Verify Code")