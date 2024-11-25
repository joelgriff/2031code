from flask import Blueprint, render_template, flash, redirect, url_for, session
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

    if session.get('invalid_attempts',0) >= 3:
        if form.validate_on_submit():
            return redirect(url_for('login'))
        return render_template('login.html', form=None, locked=True)

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and user.verify_password(form.password.data):
            session['invalid_attempts'] = 0
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('posts.posts'))
        else:
            invalid_attempts = session.get('invalid_attempts', 0) + 1
            session['invalid_attempts'] = invalid_attempts
            remaining_attempts = 3 - invalid_attempts
            flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'danger')

    return render_template('accounts/login.html', form=form)

@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')

@accounts_bp.route('/unlock', methods=['GET'])
def unlock_user():
    session['invalid_attempts'] = 0
    flash('Your account has been unlocked. You can now try logging in again.', 'success')
    return redirect(url_for('login'))