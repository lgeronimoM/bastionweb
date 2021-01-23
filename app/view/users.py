from flask import render_template, redirect, url_for, request, jsonify, session, flash
import os, requests, json, sys

# APP MVC
from app import app, cf, login_manager, db
from app.models import Servers, Users

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
from sqlalchemy import and_, or_

LOG_FILENAME = datetime.now().strftime(cf.LOG_DIR)
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(filename=LOG_FILENAME,level=cf.LOG_LEVEL)
logging.info('Comenzando la aplicacion...')

############################################# manage users ####################################

url_api_ansible = "http://"+cf.SERVER+":"+str(cf.PRTO)+"/core/v1.0/ansible"
headers = {"Content-type": "application/json"}
urlservers = cf.APISERVERS
urlusers = cf.APIUSERS
urlbastion = cf.APIBASTION
urlaccess = cf.APIACCESS

@app.route('/users', methods=['GET'], defaults={"page_num": 1})
@app.route('/users/<int:page_num>', methods=['GET'])
@login_required
def users(page_num):
    statususer = ''
    if request.args.get('statususer'):
        statususer=request.args.get('statususer')
        print(statususer)
    logging.info('Access page users')
    user = current_user.username
    apiusers=db.session.query(Users).paginate(per_page=5, page=page_num, error_out=True)
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    return render_template('users.html', user=user, data=apiusers, mail=mail)

@app.route('/adduser', methods=['POST'])
@login_required
def adduser():
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    return render_template('adduser.html', user=user, mail=mail)

@app.route('/comadduser', methods=['POST'])
@login_required
def comadduser():
    user = str(request.form['username'])
    passwd = str(request.form['password'])
    mail = str(request.form['email'])
    dep = str(request.form['area'])
    groups = str(request.form['group'])
    active = request.form.get('useractive')
    accessweb = request.form.get('webaccess')
    queryuser =  db.session.query(Users).filter(or_(Users.username==user, Users.email==mail)).first()
    if queryuser:
        flash('Ya existe '+user+' o el '+mail+' verificalo')
        logging.warning('Ya tiene acceso a bastion '+user)
        return redirect(url_for('users'))
    else:
        if active:
            active=True
        else:
            active=False
        if accessweb:
            accessweb=True
        else:
            accessweb=False
        insertQuery = Users(user,passwd,mail,dep,groups,active,accessweb)
        db.session.add(insertQuery)
        logging.info('Add user'+' '+user)
        db.session.commit()
        return redirect(url_for('users'))

@app.route('/deleteuser', methods=['POST'])
@login_required
def deleteuser():
    idf = int(request.form['id'])
    url = cf.APIUSERS
    hosting = requests.get(url, headers=headers, verify=False).json()
    db.session.query(Users).filter(Users.id == idf).delete(synchronize_session=False)
    db.session.commit()
    return redirect(url_for('users'))

@app.route('/edituser', methods=['POST'])
@login_required
def edituser():
    idf = request.form['conf']
    url = cf.APIUSERS+'/'+idf
    apiusers = requests.get(url, headers=headers, verify=False).json()
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    return render_template('edituser.html', user=user, mail=mail, apiusers=apiusers)

@app.route('/updateuser', methods=['POST'])
@login_required
def updateuser():
    idf=int(request.form['idf'])
    username=request.form['username']
    queryuser = db.session.query(Users).filter(Users.id == idf).first()
    psswd=queryuser.password
    email=request.form['email']
    group=request.form['group']
    area=request.form['area']
    active = request.form['status']
    webaccess = request.form['webaccess']
    if request.form['psswd-new']:
        psswd=request.form['psswd-new']
    if active == "1":
        active=True
    else:
        active=False
    if webaccess == "1":
        webaccess=True
    else:
        webaccess=False
    db.session.query(Users).filter(Users.id == idf).update({'username':username,'password':psswd,'email':email,'area':area,'group':group,'status':active, 'web': webaccess})
    db.session.commit()
    logging.info('Edit user '+username)
    return redirect(url_for('users'))

######################################### Login ############################3########

@app.route('/login', methods=['POST'])
def login():
    post_user = str(request.form['username'])
    post_pass = str(request.form['password'])
    validateUser = Users.query.filter(and_(Users.username==post_user, Users.password==post_pass)).first()
    if validateUser:
        if validateUser.web:
            logging.info('User '+post_user+' ok')
            getUser = Users.query.filter_by(username=post_user).first()
            login_user(getUser, remember=False)
            return redirect(url_for('home'))
        else:
            flash(post_user+' no tienen permisos suficientes')
            logging.warning('No es un usuario autorizado '+post_user)
            return redirect(url_for('home'))
    else:
        flash('Usuario o contraseña incorrectos')
        logging.warning('Error to authentication user '+post_user)
        return redirect(url_for('home'))

@app.route("/logout")
@login_required
def logout():
    logging.info('logout')
    logout_user()
    return redirect(url_for('home'))

######################## API ##################################

@app.route('/core/v1.0/users')
def apiuser():
    query = db.session.query(Users).all()
    art=[]
    for res in query:
        data ={'username': res.username, 'group': res.group, 'email': res.email, 'area': res.area, 'web': res.web, 'status':res.status, 'id':res.id }
        art.append(data)
    db.session.commit()
    return jsonify(art), 200

@app.route('/core/v1.0/users/<id>')
def apiuserfilt(id):
    art=[]
    query = db.session.query(Users).filter(Users.id.in_([id])).all()
    for res in query:
        data = {'username': res.username, 'group': res.group, 'email': res.email, 'area': res.area, 'status':res.status, 'web': res.web, 'id':res.id }
    db.session.commit()
    return jsonify(data), 200