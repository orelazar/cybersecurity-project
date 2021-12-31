from flask_login import UserMixin
from app import db, login_manager
from app.base.util import hash_pass
from datetime import datetime

class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(512))
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    retries = db.Column(db.Integer)
    locked = db.Column(db.Boolean)
    token = db.Column(db.String(100))
    token_date = db.Column(db.DateTime)

    def __init__(self, username, password, firstname, lastname, email, retries=0, locked=False, token="", token_date=datetime.now()):
        self.username = username
        self.password = hash_pass(password)
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.retries = retries
        self.locked = locked
        self.token = token
        self.token_date = token_date

    def __repr__(self):
        return str(self.username)


class Client(db.Model, UserMixin):
    __tablename__ = 'Client'
    id = db.Column(db.Integer, primary_key=True)
    clientname = db.Column(db.String(100))
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    city = db.Column(db.String(100))

    def __init__(self, clientname, firstname, lastname, email, city):
        self.clientname = clientname
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.city = city

class Passwords(db.Model, UserMixin):
    __tablename__ = 'Passwords'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(512))

    def __init__(self, username, password):
        self.username = username
        self.password = hash_pass(password)

@login_manager.user_loader
def user_loader(id):
    return User.query.filter_by(id=id).first()


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    return user if user else None
