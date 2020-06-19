__author__ = 'Luis Geronimo'
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask import redirect, url_for
from flask_login import  UserMixin, current_user

from app import db, cf

class Domain(db.Model):
    __tablename__ = "domain"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    name =  db.Column(db.String(50), nullable=False)
    typevalue =  db.Column(db.String(50), nullable=False)
    value =  db.Column(db.String(50), nullable=False)
    active =  db.Column(db.Boolean, default=False, nullable=False)
    host =  db.Column(db.Integer, db.ForeignKey('hosting.id'), nullable=False)
    #host =  db.Column(db.String(50), db.ForeignKey('hosting.zone'), nullable=False)
    zone =  db.relationship('Hosting', backref=db.backref('hosting', lazy=True))

    def get_id(self):
        return self.id

    def __init__(self, name=None, typevalue=None, value=None, active=None, host=None):
        self.name = name
        self.typevalue = typevalue
        self.value = value
        self.active = active
        self.host = host

    def __repr__(self):
        return  self.name  

class Hosting(db.Model):
    __tablename__ = "hosting"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    zone = db.Column(db.String(50), nullable=False)
    domain =  db.Column(db.String(50), nullable=False)

    def __init__(self, zone=None, domain=None):
        self.zone = zone
        self.domain = domain

    def __repr__(self):
        return self.zone

class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    username =  db.Column(db.String(50), nullable=False)
    password =  db.Column(db.String(50), nullable=False)
    email =  db.Column(db.String(50), nullable=False)
    area =  db.Column(db.String(50), nullable=False)
    admin =  db.Column(db.Boolean, default=False, nullable=False)
    id_rol =  db.Column(db.Integer, db.ForeignKey('rols.id'), nullable=False)
    rol =  db.relationship('Rols', backref=db.backref('user', lazy=True))

    def __init__(self, username=None, password=None, email=None, area=None, admin=None, id_rol=None):
        self.username = username
        self.password = password
        self.email = email
        self.area = area
        self.admin = admin
        self.id_rol = id_rol

    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return self.id
    
    def is_admin(self):
        return self.admin

    def __repr__(self):
        return '<Usuario %r>' % self.username
#----------------------------------------------------------------------
class Rols(db.Model):
    __tablename__ = "rols"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    rolname = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return self.rolname

class Register(db.Model):
    __tablename__ = "register"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    register = db.Column(db.Integer, nullable=False)
    registerdate = db.Column(db.String(50), nullable=False)
    registertype = db.Column(db.String(50), nullable=False)
    registerdomain = db.Column(db.String(50), nullable=False)

    def __init__(self, register=None, registerdate=None, registertype=None, registerdomain=None):
        self.register = register
        self.registerdate = registerdate
        self.registertype = registertype
        self.registerdomain = registerdomain

    def __repr__(self):
        return self.register

class Master(db.Model):
    __tablename__ = "master"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ipmaster = db.Column(db.String(50), nullable=False)
    user = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)

    def __init__(self, ipmaster=None, user=None, password=None):
        self.ipmaster = ipmaster
        self.user = user
        self.password = password

    def __repr__(self):
        return self.ipmaster

class Slaves(db.Model):
    __tablename__ = "slave"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ipslave = db.Column(db.String(50), nullable=False)
    user = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)

    def __init__(self, ipslave=None, user=None, password=None):
        self.ipslave = ipslave
        self.user = user
        self.password = password

    def __repr__(self):
        return self.ipslave

class Acls(db.Model):
    __tablename__ = "acl"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ipacl = db.Column(db.String(50), nullable=False)

    def __init__(self, ipacl=None):
        self.ipacl = ipacl

    def __repr__(self):
        return self.ipacl

class Forwards(db.Model):
    __tablename__ = "forward"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ipforward = db.Column(db.String(50), nullable=False)

    def __init__(self, ipforward=None):
        self.ipforward = ipforward

    def __repr__(self):
        return self.ipforward

class AdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated
    def inaccessible_callback(self, username, **kwargs):
        # redirect to login page if user doesn't have access
        return redirect(url_for('home'))