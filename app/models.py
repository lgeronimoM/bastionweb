__author__ = 'Luis Geronimo'
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask import redirect, url_for
from flask_login import  UserMixin, current_user
from datetime import datetime, timedelta
import pytz
from app import db, cf

def mexico_city_datetime():
    mexico_timezone = pytz.timezone('America/Mexico_City')
    return datetime.now(mexico_timezone)

class Servers(db.Model):
    __tablename__ = "servers"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    hostname =  db.Column(db.String(50), nullable=False)
    namekey = db.Column(db.String(50), nullable=False)
    description =  db.Column(db.String(50), nullable=False)
    dns =  db.Column(db.String(50), nullable=False)
    tipe =  db.Column(db.String(50), nullable=False)
    department =  db.Column(db.String(50), nullable=False)
    localation =  db.Column(db.String(50), nullable=False)
    ipadmin =  db.Column(db.String(50), nullable=False)
    ipprod =  db.Column(db.String(50), nullable=False)
    service =  db.Column(db.String(50), nullable=False)
    hypervisor =  db.Column(db.String(50), nullable=False)
    os =  db.Column(db.String(50), nullable=False)
    ram =  db.Column(db.String(50), nullable=False)
    cpu =  db.Column(db.String(50), nullable=False)
    storage =  db.Column(db.String(50), nullable=False)
    active =  db.Column(db.Boolean, default=False, nullable=False)
    
    def get_id(self):
        return self.id

    def __init__(self, hostname=None, namekey=None, description=None, dns=None, tipe=None, department=None, localation=None, ipadmin=None, ipprod=None, service=None, hypervisor=None, os=None, ram=None, cpu=None, storage=None, active=None):
        self.hostname = hostname
        self.namekey = namekey
        self.description = description
        self.dns = dns
        self.tipe = tipe
        self.department = department
        self.localation = localation
        self.ipadmin = ipadmin
        self.ipprod = ipprod
        self.service = service
        self.hypervisor = hypervisor
        self.os = os
        self.ram = ram
        self.cpu = cpu
        self.storage = storage
        self.active = active

    def __repr__(self):
        return  self.username

class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    username =  db.Column(db.String(50), nullable=False)
    password =  db.Column(db.String(50), nullable=False)
    email =  db.Column(db.String(50), nullable=False)
    area =  db.Column(db.String(50), nullable=False)
    status =  db.Column(db.Boolean, default=False, nullable=False)
    web =  db.Column(db.Boolean, default=False, nullable=False)
   
    def __init__(self, username=None, password=None, email=None, area=None, status=None, web=None):
        self.username = username
        self.password = password
        self.email = email
        self.area = area
        self.status = status
        self.web = web
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return self.active
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return self.id
    
    def __repr__(self):
        return  self.username
    
class Groups(db.Model):
    __tablename__ = "groups"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    name =  db.Column(db.String(50), nullable=False)
    desc =  db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, default=mexico_city_datetime, nullable=False)
   
    def __init__(self, name=None, desc=None):
        self.name = name
        self.desc = desc
        
    def __repr__(self):
        return  self.name
    
class UGRelation(db.Model):
    __tablename__ = "ugrelation"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_user =  db.Column(db.Integer, nullable=False)
    id_group =  db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=mexico_city_datetime, nullable=False)
   
    def __init__(self, id_user=None, id_group=None):
        self.id_user = id_user
        self.id_group = id_group
        
    def __repr__(self):
        return  self.id_user

class GSRelation(db.Model):
    __tablename__ = "gsrelation"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    typeug =  db.Column(db.String(10), nullable=False)
    idug =  db.Column(db.Integer, nullable=False)
    idserver =  db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=mexico_city_datetime, nullable=False)
   
    def __init__(self, idug=None, idserver=None, typeug=None):
        self.idug = idug
        self.idserver = idserver
        self.typeug = typeug
        
    def __repr__(self):
        return  self.idserver
    
class Policy(db.Model):
    __tablename__ = "policy"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    name =  db.Column(db.String(50), nullable=False)
    desc =  db.Column(db.String(200), nullable=False)
    policy = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=mexico_city_datetime, nullable=False)
   
    def __init__(self, desc=None, name=None, policy=None):
        self.desc = desc
        self.name = name
        self.policy = policy
    
    def __repr__(self):
        return  self.name
    
class UGPolicies(db.Model):
    __tablename__ = "ugpolicies"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    type_ug =  db.Column(db.String(50), nullable=False)
    id_ug =  db.Column(db.Integer, nullable=False)
    id_policy =  db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=mexico_city_datetime, nullable=False)
   
    def __init__(self, type_ug=None, id_ug=None, id_policy=None):
        self.type_ug = type_ug
        self.id_ug = id_ug
        self.id_policy = id_policy
    
    def __repr__(self):
        return  self.type_ug
    
class Access(db.Model):
    __tablename__ = "access"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    tipe =  db.Column(db.String(50), nullable=False)
    keypair =  db.Column(db.String(50), nullable=False)
    keyqr =  db.Column(db.String(50), nullable=False)
    server =  db.Column(db.String(50), nullable=False)
    user =  db.Column(db.String(50), nullable=False)
    serverid =  db.Column(db.Integer, nullable=False)
    userid =  db.Column(db.Integer, nullable=False)
    
    def get_id(self):
        return self.id

    def __init__(self, tipe=None, keypair=None, keyqr=None, server=None, user=None,serverid=None, userid=None):
        self.tipe = tipe
        self.keypair = keypair
        self.keyqr = keyqr
        self.server = server
        self.user = user
        self.serverid = serverid
        self.userid = userid

    def __repr__(self):
        return  self.tipe

class Bastion(db.Model):
    __tablename__ = "bastion"
    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    dns =  db.Column(db.String(50), nullable=False)
    bastion =  db.Column(db.String(50), nullable=False)
    idbastion =  db.Column(db.String(50), nullable=False)
    location =  db.Column(db.String(50), nullable=False)
    ip= db.Column(db.String(50), nullable=False)

    def get_id(self):
        return self.id

    def __init__(self, dns=None, bastion=None, idbastion=None, location=None, ip=None):
        self.dns = dns
        self.bastion = bastion
        self.idbastion = idbastion
        self.location = location
        self.ip = ip
       

    def __repr__(self):
        return  self.bastion

class AdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated
    def inaccessible_callback(self, username, **kwargs):
        #redirect to login page if user doesn't have access
        return redirect(url_for('home'))