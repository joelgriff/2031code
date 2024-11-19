import secrets
from crypt import methods
from struct import error

import limiter
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from sqlalchemy.sql.functions import user

from accounts.forms import RegistrationForm
from config import User, db
from flask_login import login_user, current_user, login_required
from accounts.forms import LoginForm
from config import User
from werkzeug.security import check_password_hash
from config import attempt_limiter



accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()

    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        )

        db.session.add(new_user)
        db.session.commit()

        flash('Account Created, Please set up MFA before logging in', category='success')
        return redirect(url_for('accounts.MFA_setup', mfa_key=new_user.mfa_key))

    return render_template('accounts/registration.html', form=form)

MAX_ATTEMPTS = 3


@accounts_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.verify_password(form.password.data):
            if not user.mfa_enabled:
                flash('MFA is not set up. Please set it up to proceed.', 'warning')
                login_user(user)
                return redirect(url_for('accounts.MFA_setup'))

            # Check if the user is authenticated before verifying MFA PIN
            if current_user.is_authenticated:
                pin = form.mfa_pin.data
                totp = pyotp.TOTP(user.mfa_key)
                if totp.verify(pin):
                    login_user(user)
                    flash('Logged in successfully.', 'success')
                    return redirect(url_for('posts.posts'))
                else:
                    flash('Invalid MFA PIN.', 'danger')
            else:
                flash('Please log in first.', 'warning')
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('accounts/login.html', form=form)

@accounts_bp.route('/user_unlock', methods=['GET'])
def user_unlock():
    session.pop('failed_attempts', None)
    flash('Successfully unlocked account, Please log in again.', 'success')
    return redirect(url_for('accounts.login'))


@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')

@accounts_bp.route('/MFA_setup', methods=['GET', 'POST'])
@login_required  # Ensure the user is authenticated before accessing their data
def MFA_setup():
    # Check if the user is already authenticated and has MFA enabled
    if current_user.mfa_enabled:
        flash("MFA is already enabled", 'info')
        return redirect(url_for('posts.posts'))

    mfa_key = current_user.mfa_key
    otp_url = pyotp.TOTP(mfa_key).provisioning_uri(
        name=current_user.email,
        issuer_name='app'
    )

    # Handle POST request for setting up MFA
    if request.method == 'POST':
        pin = request.form.get('mfa_pin')
        totp = pyotp.TOTP(mfa_key)

        # Verify the MFA PIN entered by the user
        if totp.verify(pin):
            current_user.mfa_enabled = True
            db.session.commit()
            flash('MFA has been successfully set up for your account.', 'success')
            return redirect(url_for('posts.posts'))  # Redirect to posts or dashboard
        else:
            flash('Invalid MFA PIN. Please try again.', 'danger')

    return render_template('MFA_setup.html', otp_url=otp_url)