from crypt import methods
from struct import error

import limiter
from flask import Blueprint, render_template, flash, redirect, url_for, session
from accounts.forms import RegistrationForm
from config import User, db
from flask_login import login_user
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

        flash('Account Created', category='success')
        return redirect(url_for('accounts.login'))

    return render_template('accounts/registration.html', form=form)

MAX_ATTEMPTS = 3
@accounts_bp.route('/login', methods=['GET', 'POST'])
@attempt_limiter.limit("20 per minute")
def login():

    failed_attempts = session.get('failed_attempts', 0)

    if failed_attempts >= 3:
        return render_template('accounts/lock.html')

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user is None or not user.verify_password(password):
            failed_attempts += 1
            session['failed_attempts'] = failed_attempts

            flash(f'Invalid email or password. You have {3 - failed_attempts} attempts left.', 'danger')
            return redirect(url_for('accounts.login'))

        session.pop('failed_attempts', None)
        flash('Login successful', 'success')
        return redirect(url_for('posts'))

    return render_template('accounts/login.html', form=form)

@accounts_bp.route('/user_unlock', methods=['GET'])
def user_unlock():
    session.pop('failed_attempts', None)
    flash('Successfully unlocked account, Please log in again.', 'success')
    return redirect(url_for('accounts.login'))


@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')