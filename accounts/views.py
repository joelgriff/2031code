from flask import Blueprint, render_template, flash, redirect, url_for
from flask_sqlalchemy import session

from accounts.forms import RegistrationForm
from config import User, db
from flask_login import login_user
from accounts.forms import LoginForm
from config import User
from werkzeug.security import check_password_hash


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

@accounts_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    max_login_attempts = 3

    if 'failed_attempt' not in session:
        session['failed_attempts'] = 0

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user is None or not user.verify_password(password):
            flash('Invalid email or password', 'danger')
            session['failed_attempts'] += 1
            attempts_remaining = max_login_attempts - session['failed_attempts']
            return redirect(url_for('login'))

            if attempts_remaining > 0:
                flash(f'You have failed to login, {attempts_remaining} left.' , 'danger')
                return redirect(url_for('accounts.login'))
            else:
                flash('Too many failed logins. Try again later')
                return redirect(url_for('accounts.login'))


        session.pop('failed_attempts', None)
        flash('Login successful', 'success')
        return redirect(url_for('posts'))

    return render_template('accounts/login.html', form=form)

@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')