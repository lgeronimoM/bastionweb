from flask import render_template, redirect, url_for, request, jsonify, session, Blueprint, flash
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
        
######################################### global vars ##############################3

url_api_ansible = "http://"+cf.SERVER+":"+str(cf.PRTO)+"/core/v1.0/ansible"
headers = {"Content-type": "application/json"}
urlservers = cf.APISERVERS
urlusers = cf.APIUSERS
urlbastion = cf.APIBASTION
urlaccess = cf.APIACCESS

####################### Endpoints #############################

@app.route('/servers', methods=['GET'], defaults={"page_num": 1})
@app.route('/servers/<int:page_num>', methods=['GET'])
@login_required
def servers(page_num):
    apiservers=db.session.query(Servers).paginate(per_page=10, page=page_num, error_out=True)
    filtro=request.args.get('findserver')
    findservers=False
    statusserver= ''
    if request.args.get('statusserver'):
        statusserver=request.args.get('statusserver')
    if filtro:
        search = "%{}%".format(filtro)
        apiservers=db.session.query(Servers).filter(Servers.namekey.like(search)).paginate(per_page=10, page=page_num, error_out=True)
        findservers=True
    logging.info('Access page servers')
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    return render_template('servers.html', user=user, data=apiservers, mail=mail, findservers=findservers, statusserver=statusserver, findserver=filtro)

@app.route('/addserver', methods=['POST','GET'])
@login_required
def addserver():
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    validated = request.args.get('validate', '')
    return render_template('addserver.html', user=user, mail=mail, validated=validated)

@app.route('/comaddserver', methods=['POST'])
@login_required
def comaddserver():
    host = str(request.form['hostname'])
    name = str(request.form['name'])
    descripcion = str(request.form['descripcion'])
    dns = str(request.form['dns'])
    tipo = str(request.form['tipo'])
    departamento = str(request.form['departamento'])
    localidad = str(request.form['localidad'])
    ipadmin = str(request.form['ipadmin'])
    ippro = str(request.form['ippro'])
    servicio = str(request.form['servicio'])
    hipervisor = str(request.form['hipervisor'])
    sistema = str(request.form['sistema'])
    ram = str(request.form['ram'])
    cpu = str(request.form['cpu'])
    disco = str(request.form['disco'])
    insertQuery = Servers(host,name,descripcion,dns,tipo,departamento,localidad,ipadmin,ippro,servicio,hipervisor,sistema,ram,cpu,disco,True)
    queryserver =  db.session.query(Servers).filter(or_(Servers.hostname==host, Servers.ipadmin==ipadmin, Servers.namekey==name)).first()
    if queryserver:
        #statusadd='Ya existe '+host+' o ip '+ipadmin+' verificalo'
        logging.warning('Ya tiene acceso a bastion '+host)
        return redirect(url_for('addserver', validate='Ya existe host o ip favor de validar'))
    else:
        db.session.add(insertQuery)
    logging.info('Add server'+' '+name)
    db.session.commit()
    return redirect(url_for('servers'))

@app.route('/deleteserver', methods=['POST'])
@login_required
def deleteserver():
    idf = int(request.form['id'])
    db.session.query(Servers).filter(Servers.id == idf).delete(synchronize_session=False)
    logging.info('delete server')
    db.session.commit()
    return redirect(url_for('servers'))

@app.route('/editserver', methods=['POST'])
@login_required
def editserver():
    if request.form['update_button']:
        idf = request.form['update_button']
        url = cf.APISERVERS+'/'+idf
        headers = {'Content-type': 'application/json'}
        apiservers = requests.get(url, headers=headers, verify=False).json()
        user = current_user.username
        queryuser = db.session.query(Users).filter(Users.username==user).first()
        mail = queryuser.email
        return render_template('editserver.html', user=user, mail=mail, apiservers=apiservers)

@app.route('/updateserver', methods=['POST'])
@login_required
def updateserver():
    idf=int(request.form['idf'])
    host = str(request.form['hostname'])
    name = str(request.form['name'])
    descripcion = str(request.form['descripcion'])
    dns = str(request.form['dns'])
    tipo = str(request.form['tipe'])
    departamento = str(request.form['departamento'])
    localidad = str(request.form['localidad'])
    ipadmin = str(request.form['ipadmin'])
    ippro = str(request.form['ippro'])
    servicio = str(request.form['servicio'])
    hipervisor = str(request.form['hipervisor'])
    sistema = str(request.form['sistema'])
    ram = str(request.form['ram'])
    cpu = str(request.form['cpu'])
    disco = str(request.form['disco'])
    estatus = int(request.form['estatus'])
    logging.info('Edit server'+' '+host)
    db.session.query(Servers).filter(Servers.id == idf).update({'hostname':host, 'namekey':name, 'description':descripcion, 'dns':dns, 'tipe':tipo, 'department':departamento, 'localation':localidad, 'ipadmin':ipadmin, 'ipprod':ippro, 'service':servicio, 'hypervisor':hipervisor, 'os':sistema, 'ram':ram, 'cpu':cpu, 'storage':disco, 'active':bool(estatus)})
    db.session.commit()
    return redirect(url_for('servers'))

######################## API ##################################

@app.route('/core/v1.0/servers')
def apiservers():
    resul = db.session.query(Servers).all()
    art=[]
    for res in resul:
        dict ={'hostname': res.hostname,  'namekey': res.namekey, 'descripcion': res.description, 'tipo': res.tipe, 'dns': res.dns,
        'departamento':res.department, 'ubicacion':res.localation, 'ipadmin':res.ipadmin, 'ipprod':res.ipprod,
        'servicio':res.service, 'hypervisor':res.hypervisor, 'sistema':res.os, 'ram':res.ram, 'cpu':res.cpu,
        'almacenamiento':res.storage, 'estado':res.active,'id':res.id }
        art.append(dict)
    db.session.commit()
    return jsonify(art), 200

@app.route('/core/v1.0/servers/<id>')
def apiserverfilt(id):
    query = db.session.query(Servers).filter(Servers.id.in_([id])).all()
    for res in query:
        data = {'hostname': res.hostname, 'namekey': res.namekey, 'descripcion': res.description, 'tipo': res.tipe, 'dns': res.dns,
        'departamento':res.department, 'ubicacion':res.localation, 'ipadmin':res.ipadmin, 'ipprod':res.ipprod,
        'servicio':res.service, 'hypervisor':res.hypervisor, 'sistema':res.os, 'ram':res.ram, 'cpu':res.cpu,
        'almacenamiento':res.storage, 'estado':res.active,'id':res.id }
    db.session.commit()
    return jsonify(data), 200