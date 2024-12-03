from flask_login import login_required

from config import app
from flask import render_template, jsonify


@app.route('/')
def index():
    return render_template('home/index.html')

@app.errorhandler(429)
def ratelimit_error(e):
    return render_template("errors/rateLimit.html")

@app.route('/account')
def account():
    return render_template('accounts/account.html')

@app.route('/registration')
def registration():
    return render_template('accounts/registration.html')

@app.route('/login')
def login():
    return render_template('accounts/login.html')


@app.route('/create')
def create():
    return render_template('posts/create.html')

@app.route('/posts')
def posts():
    return render_template('posts/posts.html')

@app.route('/registration')
def update():
    return render_template('posts/update.html')

@app.route('/security')
def security():
    return render_template('security/security.html')


if __name__ == '__main__':
    app.run()

