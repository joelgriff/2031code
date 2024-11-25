from datetime import datetime

import pyotp
from flask import Flask, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import UserMixin, login_manager, current_user, LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets


app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)

# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = secrets.token_hex(16)

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdgyVUqAAAAAOlpHkzRlx7dr2F0SYp3QTp5Mo96'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdgyVUqAAAAANmq8UrWlHqa4taLr7ZR8nJWh_Pd'

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///csc2031blog.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True

metadata = MetaData(
    naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
    }
)

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)

# DATABASE TABLES
class Post(db.Model, UserMixin):
   __tablename__ = 'posts'

   id = db.Column(db.Integer, primary_key=True)
   userid = db.Column(db.Integer, db.ForeignKey('users.id'))
   created = db.Column(db.DateTime, nullable=False)
   title = db.Column(db.Text, nullable=False)
   body = db.Column(db.Text, nullable=False)
   user = db.relationship("User", back_populates="posts")

   def __init__(self, title, body):
       self.created = datetime.now()
       self.title = title
       self.body = body

   def update(self, title, body):
       self.created = datetime.now()
       self.title = title
       self.body = body
       db.session.commit()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    mfa_key=db.Column(db.String(32), nullable=False, default=lambda: secrets.token_hex(16))
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    otp_uri = db.Column(db.String(100), nullable=False)

    posts = db.relationship("Post", order_by=Post.id, back_populates="user")

    def __init__(self, email, firstname, lastname, phone, password, mfa_key=None, otp_uri=None):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password_hash = generate_password_hash(password)
        self.mfa_key = pyotp.random_base32()
        self.mfa_enabled = False
        self.otp_uri = pyotp.TOTP(mfa_key).provisioning_uri(name=email,issuer_name='app')


    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, new_password):
        self.password_hash = generate_password_hash(new_password)

    def verifyPin(self, pin):
        return pyotp.TOTP(self.mfa_key).verify(pin)


# DATABASE ADMINISTRATOR
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')


class PostView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'user.email', 'created', 'title', 'body')

class UserView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'email', 'firstname', 'lastname', 'phone', 'posts', 'mfa_key', 'opt_uri')
    form_excluded_columns = ['password_hash']



admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))

## IMPORT BLUEPRINTS
from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp

## REGISTER BLUEPRINTS

app.register_blueprint(accounts_bp, name="accounts")
app.register_blueprint(posts_bp, name="posts")
app.register_blueprint(security_bp, name="security")