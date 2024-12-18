from datetime import datetime

import pyotp
from flask import Flask, url_for
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from pygments.lexer import default
from sqlalchemy import MetaData
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
from flask_login import UserMixin, LoginManager
from sqlalchemy import Boolean, String
from sqlalchemy.orm import validates
from flask_login import current_user
import pyopt


app = Flask(__name__)

attempt_limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day"]# Application-wide rate limit of 500 calls per day
)


# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = secrets.token_hex(16)

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdgyVUqAAAAAOlpHkzRlx7dr2F0SYp3QTp5Mo96'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdgyVUqAAAAANmq8UrWlHqa4taLr7ZR8nJWh_Pd'

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///csc2031blog.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

login_manager = LoginManager(app)
login_manager.login_view = 'accounts.login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# DATABASE TABLES
class Post(db.Model):
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




class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    mfa_key = db.Column(db.String(32), nullable=False, default=lambda: secrets.token_hex(16))
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")


    def __init__(self, email, firstname, lastname, phone, password):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, new_password):
        self.password_hash = generate_password_hash(new_password)

    @validates('mfa_key')
    def validate_mfa_key(self, key, value):
        if not value or len(value) not in (16, 32):
            raise ValueError("Invalid MFA key length")
        return value

    @validates('mfa_enabled')
    def validate_mfa_enabled(self, key, value):
        if not isinstance(value, bool):
            raise ValueError("MFA enabled must be a boolean")
        return value

    def __repr__(self):
        return f"User('{self.email}', MFA Enabled: {self.mfa_enabled})"



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
    column_list = ('id', 'email', 'firstname', 'lastname', 'phone', 'posts')
    form_excluded_columns = ['password_hash',]

    def give_access(self):
        return current_user.is_authenticated and current_user.is_admin

app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True


admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))

Limit_attempt = Limiter(
    key_func=get_remote_address,
    default_limits= ["500 each day", "20 each minute"]
)

## IMPORT BLUEPRINTS
from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp

## REGISTER BLUEPRINTS

app.register_blueprint(accounts_bp, name="accounts")
app.register_blueprint(posts_bp, name="posts")
app.register_blueprint(security_bp, name="security")