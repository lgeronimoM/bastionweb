# This file contains the Flask app configuration and imports the necessary modules.
__author__ = 'Luis Geronimo'
from flask import Flask

# Entorno
from flask_environments import Environments

# SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import sessionmaker

# Login manager
from flask_login import LoginManager

import hmac

app = Flask(__name__)

if app.config["ENV"] == "production":
    app.config.from_object("properties.ProductionConfig")
elif app.config["ENV"] == "development":
    app.config.from_object("properties.DevelopmentConfig")
else:
    app.config.from_object("properties.TestingConfig")

class cf():
    SECRETKEY=app.config["SECRETKEY"]
    SERVER=app.config["SERVER"]
    PRTO=app.config["PRTO"]
    PORT_SMTP=app.config["PORT_SMTP"]
    HOST_SMTP=app.config["HOST_SMTP"]
    USER_SMTP=app.config["USER_SMTP"]
    PASS_SMTP=app.config["PASS_SMTP"]
    RECIVE_MAILS=app.config["RECIVE_MAILS"]
    DIRFILEQR=app.config["DIRFILEQR"]
    DIRFILEPEM=app.config["DIRFILEPEM"]
    DB_DIR=app.config["DB_DIR"]
    LINK=app.config["LINK"]
    TEM=app.config["TEM"]
    USERANS=app.config["USERANS"]
    PASSWDANS=app.config["PASSWDANS"]
    PRIVATEKEY=app.config["PRIVATEKEY"]
    HOSTANS=app.config["HOSTANS"]
    MAINAPP=app.config["MAINAPP"]
    NAMEAPP=app.config["NAMEAPP"]
    APISERVERS=app.config["APISERVERS"]
    APIUSERS=app.config["APIUSERS"]
    APIBASTION=app.config["APIBASTION"]
    APIACCESS=app.config["APIACCESS"]
    LOG_DIR=app.config["LOG_DIR"]
    LOG_LEVEL=app.config["LOG_LEVEL"]
    DEBUG=app.config["DEBUG"]
    RUTALOG=app.config["RUTALOG"]
    VARSFILE=app.config['VARSFILE']
    DIRFILES=app.config['DIRFILES']

app.config['SECRET_KEY'] = cf.SECRETKEY
app.config['SQLALCHEMY_DATABASE_URI'] = cf.DB_DIR
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)

from app.view import home
from app.view import servers
from app.view import bastion
from app.view import users
from app.view import permissions