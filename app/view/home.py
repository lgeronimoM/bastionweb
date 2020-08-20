from flask import render_template, redirect, url_for, request, jsonify, session
import os, requests, json, sys

# APP MVC
from app import app, cf, login_manager, db
from app.models import Servers, Users, Access, Bastion

# MAIL
import email, smtplib, ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Files yaml
import yaml

# Graficas
import pygal
from pygal.style import NeonStyle
from pygal.style import Style

#Logs
import logging
from datetime import datetime #Fecha logs
from datetime import date
from datetime import timedelta #Graficas

#System
import os, requests, json

#login
from flask_login import UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.orm import sessionmaker
from sqlalchemy import desc
from sqlalchemy import and_

LOG_FILENAME = datetime.now().strftime(cf.LOG_DIR)
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(filename=LOG_FILENAME,level=cf.LOG_LEVEL)
logging.info('Comenzando la aplicacion...')

headers = {"Content-type": "application/json"}
urlservers = cf.APISERVERS
urlusers = cf.APIUSERS
urlbastion = cf.APIBASTION
urlaccess = cf.APIACCESS
inventoryfile = cf.HOSTANS
playbookyml = cf.MAINAPP
fileprivatekey = cf.PRIVATEKEY

####################### Endpoints #############################
@app.route('/')
def home():
    is_auth = current_user.is_authenticated
    if is_auth:
        logging.info('User authentication')
        user = current_user.username
        query = db.session.query(Users).filter(Users.username==user).first()
        servers = db.session.query(Servers).all()
        serversmiami = db.session.query(Servers).filter(Servers.localation=='miami')
        serversaws = db.session.query(Servers).filter(Servers.localation=='aws')
        serversotros = db.session.query(Servers).filter(and_(Servers.localation!='aws',Servers.localation!='miami'))
        accessclient = db.session.query(Access).filter(Access.tipe=='client')
        accessserver = db.session.query(Access).filter(Access.tipe=='server')
        client = db.session.query(Users).all()
        clientweb = db.session.query(Users).filter(Users.web==True)
        bastion = db.session.query(Bastion).all()
        if bastion:
            pass
        mail = query.email
        return render_template('index.html',user=user,mail=mail,servers=servers,client=client,clientweb=clientweb,serversotros=serversotros,serversmiami=serversmiami,serversaws=serversaws,accessclient=accessclient,accessserver=accessserver,bastion=bastion )
    else:
        logging.info('User trying access to page')
        return render_template('login.html')

########################################### API Ansible-Playbooks ###################################################