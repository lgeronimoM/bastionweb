from flask import render_template, redirect, url_for, request, jsonify, session, Blueprint, flash
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

# Graficas
import pygal
from pygal.style import NeonStyle 
from pygal.style import Style

#packages ansible
from ansible import context
from ansible.cli import CLI
from ansible.module_utils.common.collections import ImmutableDict
from ansible.executor.playbook_executor import PlaybookExecutor
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager

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
        
######################################### global vars ##############################3

url_api_ansible = "http://"+cf.SERVER+":"+str(cf.PRTO)+"/core/v1.0/ansible"
url_api_ansible_mul = "http://"+cf.SERVER+":"+str(cf.PRTO)+"/core/v2.0/ansible/multi"
headers = {"Content-type": "application/json"}
urlservers = cf.APISERVERS
urlusers = cf.APIUSERS
urlbastion = cf.APIBASTION
urlaccess = cf.APIACCESS
inventoryfile = cf.HOSTANS
playbookyml = cf.MAINAPP
fileprivatekey = cf.PRIVATEKEY
userans = cf.USERANS
port_smtp=cf.PORT_SMTP
host_smtp=cf.HOST_SMTP
user_smtp=cf.USER_SMTP
pass_smtp=cf.PASS_SMTP
dirfilepem=cf.DIRFILEPEM
dirfileqr=cf.DIRFILEQR
reception_mails=cf.RECIVE_MAILS
serverlocal=cf.SERVER
rutalogs = cf.RUTALOG
urlaccessuser = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/core/v1.0/access/user'

####################### Endpoints #############################

@app.route('/bastion', methods=['GET'], defaults={"page_num": 1})
@app.route('/bastion/<int:page_num>', methods=['GET'])
@login_required
def bastion(page_num):
    filteruser=request.args.get('filteruser')
    filterhost=request.args.get('filterhost')
    filterserver=request.args.get('findserver')
    exist = db.session.query(Bastion).filter().first()
    accessserver = db.session.query(Access).filter(Access.tipe=='server')
    apibastion=''
    nameuser=False
    nameserver=False
    if exist:
        exist=True
        apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    else:
        exist=False
    apiaccess=db.session.query(Access).paginate(per_page=10, page=page_num, error_out=True)
    if filteruser:
        queryuser = db.session.query(Users).filter(Users.id==int(filteruser)).first()
        nameuser=queryuser.username
        logging.info('Filter user on page bastion')
        apiaccess=db.session.query(Access).filter(Access.userid==int(filteruser)).paginate(per_page=10, page=page_num, error_out=True)
        if filterserver:
            search = "%{}%".format(filterserver)
            apiaccess=db.session.query(Access).filter(and_(Access.userid==int(filteruser), Access.keypair.like(search))).paginate(per_page=10, page=page_num, error_out=True)
            filterserver=True
    if filterhost:
        logging.info('Filter host on page bastion')
        apiaccess=db.session.query(Access).filter(Access.serverid==int(filterhost)).paginate(per_page=10, page=page_num, error_out=True)
    apiservers = requests.get(urlservers, headers=headers, verify=False).json()
    apiusers = requests.get(urlusers, headers=headers, verify=False).json()
    logging.info('Access page Bastion')
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    return render_template('bastion.html', filteruser=filteruser, user=user, nameuser=nameuser, apiservers=apiservers, apiusers=apiusers, apibastion=apibastion, data=apiaccess, mail=mail, exist=exist, accessserver=accessserver)

# Agregar servidor master de bastion
@app.route('/addbastion', methods=['POST'])
@login_required
def addbastion():
    idserver = str(request.form['server'])
    apiservers = requests.get(urlservers+'/'+idserver, headers=headers, verify=False).json()
    server=apiservers['hostname']
    dns=apiservers['dns']
    location=apiservers['ubicacion']
    ipadmin=apiservers['ipadmin']
    insertQuery = Bastion(dns,server,idserver,location,ipadmin)
    db.session.add(insertQuery)
    logging.info('bastion ada '+server)
    db.session.commit()
    inventory_ansible()
    return redirect(url_for('servers'))

# Eliminar servidor master de bastion
@app.route('/deletebastion', methods=['POST'])
@login_required
def deletebastion():
    idf = int(request.form['idf'])
    db.session.query(Bastion).filter(Bastion.id == idf).delete(synchronize_session=False)
    db.session.commit()
    return redirect(url_for('servers'))

def addbastionclient(iduser):
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    apiusers = requests.get(urlusers+'/'+str(iduser), headers=headers, verify=False).json()
    idserver=apibastion['idserver']
    apiservers = requests.get(urlservers+'/'+str(idserver), headers=headers, verify=False).json()
    server=apiservers['hostname']
    user=apiusers['username']
    email=apiusers['email']
    group=apiusers['group']
    ipserver=apiservers['ipadmin']
    namekey=apiservers['namekey']
    filekey=namekey+'_'+user+'.pem'
    fileqrm=namekey+'_'+user+'.txt'
    inventory_ansible()
    queryuser =  Access.query.filter(and_(Access.server==server, Access.user==user, Access.tipe=='client' )).first()
    if queryuser:
        flash('Ya existe este acceso 2', 'error')
        logging.warning('Ya tiene acceso a bastion '+user)
        return redirect(url_for('bastion', filteruser=iduser))
    else:
        var_ansible(user, group, email, ipserver, namekey)
        content={ "tagsexc": ['adduser-mfa'], "ipmanage": ipserver, "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
        r=requests.post(url_api_ansible, json=content, headers=headers, verify=False)
        result=r.json()
        if result['status']==0:
            insertQuery = Access('client',filekey,fileqrm,server,user,idserver,iduser)
            db.session.add(insertQuery)
            db.session.commit()
            logging.warning('genrado usuario: '+user)
            flash('Nuevo usuario creado '+user, 'ok')
            return redirect(url_for('bastion', filteruser=iduser))
        else:
            flash('Error al intentar Verifica la causa', 'error')
            return redirect(url_for('bastion', filteruser=iduser))
        
@app.route('/newbastionclient', methods=['POST'])
@login_required
def newbastionclient(iduser, user, email, group):
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    idserver=apibastion['idserver']
    apiservers = requests.get(urlservers+'/'+str(idserver), headers=headers, verify=False).json()
    server=apiservers['hostname']
    ipserver=apiservers['ipadmin']
    namekey=apiservers['namekey']
    filekey=namekey+'_'+user+'.pem'
    fileqrm=namekey+'_'+user+'.txt'
    inventory_ansible()
    queryuser =  Access.query.filter(and_(Access.server==server, Access.user==user, Access.tipe=='client' )).first()
    if queryuser:
        flash('Ya existe este acceso' , 'error')
        logging.warning('Ya tiene acceso a bastion '+user)
        return redirect(url_for('bastion', filteruser=iduser))
    else:
        var_ansible(user, group, email, ipserver, namekey)
        content={ "tagsexc": ['adduser-mfa'], "ipmanage": ipserver, "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
        r=requests.post(url_api_ansible, json=content, headers=headers, verify=False)
        result=r.json()
        if result['status']==0:
            insertQuery = Access('client',filekey,fileqrm,server,user,idserver,iduser)
            db.session.add(insertQuery)
            db.session.commit()
            logging.info('se crea nuevo usuario: '+user)
            flash('Nuevo usuario creado '+user, 'ok')
            return redirect(url_for('bastion', filteruser=iduser))
        else:
            flash('Error al intentar Verifica la causa', 'error')
            logging.info('Erro al generar client-bastion '+user+' '+result['status'])
            return redirect(url_for('bastion', filteruser=iduser))

@app.route('/combastion', methods=['POST'])
@login_required
def combastion():
    idaccess = request.form.get('valoresSeleccionados')
    elementos = idaccess.split(',')
    idservers = [int(elemento) for elemento in elementos]
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    ipbastion=apibastion['ip']
    for serverid in idservers:
        apiaccess = requests.get(urlaccess+'/'+str(serverid), headers=headers, verify=False).json()
        iduser = apiaccess['userid']
        idserver = apiaccess['serverid']
        apiusers = requests.get(urlusers+'/'+str(iduser), headers=headers, verify=False).json()
        apiservers = requests.get(urlservers+'/'+str(idserver), headers=headers, verify=False).json()
        ipserver=apiservers['ipadmin']
        server=apiservers['hostname']
        user=apiusers['username']
        email=apiusers['email']
        group=apiusers['group']
        namekey=apiservers['namekey']
        inventory_ansible()
        filekey=namekey+'_'+ipserver+'.pem'
        var_ansible(user, group, email, ipserver, namekey)
        content={ "tagsexc": ['adduser-host', 'permissions'], "ipmanage": ipserver, "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
        r = requests.post(url_api_ansible, json=content, headers=headers, verify=False)
        result=r.json()
        if result['status']==0:
            flash('usuario '+user+' OK', 'ok')
            db.session.query(Access).filter(Access.userid == iduser, Access.serverid == idserver).update({ 'keypair':filekey, 'server':server })
            db.session.commit()
            logging.warning('Regenerado usuario: '+user+' en el server '+ipserver)
        else:
            flash('Error al intentar Verifica la causa', 'error')
            logging.info('Erro al regenerar bastion-server '+user+' '+str(result['status']))
            return redirect(url_for('bastion', filteruser=iduser))
    return redirect(url_for('bastion'))

def deleteuserbastion(iduser):
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    idserver=apibastion['idserver']
    apiusers = requests.get(urlusers+'/'+str(iduser), headers=headers, verify=False).json()
    apiservers = requests.get(urlservers+'/'+str(idserver), headers=headers, verify=False).json()
    ipserver=apiservers['ipadmin']
    user=apiusers['username']
    email=''
    group=apiusers['group']
    namekey=apiservers['namekey']
    var_ansible(user, group, email, ipserver, namekey)
    content={ "tagsexc": ['deluser-mfa'], "ipmanage": ipserver, "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
    r = requests.post(url_api_ansible, json=content, headers=headers, verify=False)
    result=r.json()
    if result['status']==0:
        flash('Acceso de usuario '+user+' elimindo en ip '+ipserver, 'error')
        logging.warning('Eliminar usuario: '+user+' en el server '+ipserver)
        db.session.query(Access).filter(Access.serverid == idserver, Access.userid == iduser).delete(synchronize_session=False)
        db.session.commit()
        return redirect(url_for('bastion', filteruser=iduser))
    else:
        flash('Error al intentar Verifica la causa', 'error')
        logging.info('Erro al Eliminar bastion-server '+user+' '+str(result['status']))
        return redirect(url_for('bastion', filteruser=iduser))
            
@app.route('/deleteaccess', methods=['POST'])
@login_required
def deleteaccess():
    idaccess = request.form.get('valoresSeleccionados')
    elementos = idaccess.split(',')
    accessesid = [int(elemento) for elemento in elementos]
    for idaccess in accessesid:
        apiaccess = requests.get(urlaccess+'/'+str(idaccess), headers=headers, verify=False).json()
        iduser = apiaccess['userid']
        idserver = apiaccess['serverid']
        apiusers = requests.get(urlusers+'/'+str(iduser), headers=headers, verify=False).json()
        apiservers = requests.get(urlservers+'/'+str(idserver), headers=headers, verify=False).json()
        ipserver=apiservers['ipadmin']
        user=apiusers['username']
        email=''
        group=apiusers['group']
        namekey=apiservers['namekey']
        var_ansible(user, group, email, ipserver, namekey)
        content={ "tagsexc": ['deluser-server'], "ipmanage": ipserver, "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
        r = requests.post(url_api_ansible, json=content, headers=headers, verify=False)
        result=r.json()
        if result['status']==0:
            flash('Acceso de usuario '+user+' eliminado', 'error')
            logging.warning('Eliminar usuario: '+user+' en el server '+ipserver)       
            db.session.query(Access).filter(Access.id == idaccess).delete(synchronize_session=False)
            db.session.commit()
        else:
            flash('Error al intentar Verifica la causa', 'error')
            logging.info('Erro al Eliminar client-bastion '+user+' '+str(result['status']))
            return redirect(url_for('bastion', filteruser=iduser))
    return redirect(url_for('bastion', filteruser=iduser, estado='ok'))
            
@app.route("/message", methods=['POST'])
@login_required
def message():
    accessid = str(request.form['idaccess'])
    userid = str(request.form['iduser'])
    apiaccess = requests.get(urlaccess+'/'+accessid, headers=headers, verify=False).json()
    keypair = apiaccess['keypair']
    keyqr = apiaccess['keyqr'] 
    server = apiaccess['server'] 
    user = apiaccess['user']
    port = port_smtp
    smtp_server = host_smtp
    sender_email = user_smtp
    receiver_email = reception_mails
    password = pass_smtp
    subject = "Notificación"
    body = "Este mensaje es para reenviar el acceso para el usuario "+user+", el cual esta dado de alta en nuestro servidor bastion con nombre "+server+". y su email "+keypair+"\nSe contacto con usted por el siguiente problema: "+keyqr
    # Create a multipart message and set headers
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message["Bcc"] = receiver_email  # Recommended for mass emails
    # Add body to email
    message.attach(MIMEText(body, "plain"))
    text = message.as_string()
    # Log in to server using secure context and send email
    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as server:
        server.starttlsx(context=context)
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, text)
    return redirect(url_for('bastion', filteruser=userid))

@app.route('/addbastionserver', methods=['POST'])
@login_required
def addbastionserver():
    idserver = str(request.form['server'])
    iduser = str(request.form['user'])
    apiservers = requests.get(urlservers+'/'+idserver, headers=headers, verify=False).json()
    apiusers = requests.get(urlusers+'/'+iduser, headers=headers, verify=False).json()
    server=apiservers['hostname']
    user=apiusers['username']
    email=apiusers['email']
    group=apiusers['group']
    namekey=apiservers['namekey']
    ipserver=apiservers['ipadmin']
    filekey=namekey+'_'+ipserver+'.pem'
    inventory_ansible()
    queryuser =  Access.query.filter(and_(Access.server==server, Access.user==user, Access.tipe=='server' )).first()
    if queryuser:
        flash('Ya existe este acceso', 'error')
        logging.warning('Ya tiene acceso a bastion '+user)
        return redirect(url_for('bastion', filteruser=iduser))
    else:
        var_ansible(user, group, email, ipserver, namekey)
        content={ "tagsexc": [ 'permissions','adduser-host'], "ipmanage": ipserver, "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
        r=requests.post(url_api_ansible, json=content, headers=headers, verify=False)
        result=r.json()
        if result['status']==0:
            flash('Acceso de usuario '+user+' OK '+ipserver, 'ok')
            insertQuery = Access('server',filekey,'N/A',server,user,idserver,iduser)
            db.session.add(insertQuery)
            db.session.commit()
            logging.warning('genrado usuario: '+user+' en el server'+ipserver)
            return redirect(url_for('bastion', filteruser=iduser, estado='ok'))
        else:
            flash('Error al intentar Verifica la causa', 'error')
            logging.info('Erro al generar acceso a usuario '+user+' en el server '+ipserver+' Messaje de error: '+str(result['status']))
            return redirect(url_for('bastion', filteruser=iduser, estado='error'))

def copyaccessbastion(idusercopy, user, mail, groups):
    queryuser =  db.session.query(Users).filter(Users.username==user, Users.email==mail).first()
    iduser = queryuser.id
    accessuser = requests.get(urlaccessuser+'/'+str(idusercopy), headers=headers, verify=False).json()
    server_ips= []  # Lista para almacenar los serverid
    server_namekey = []
    for item in accessuser:
        server_id = item["serverid"]
        apiservers = requests.get(urlservers+'/'+str(server_id), headers=headers, verify=False).json()
        tipeserver=item['tipe']
        if tipeserver=='server':
            ipserver=apiservers['ipadmin']
            namekey=apiservers['namekey']    
            server_ips.append(ipserver)
            server_namekey.append(namekey)
    server=apiservers['hostname']    
    logging.info('runnig ansible-playbook adduser-host'+str(server_ips))
    file = open(inventoryfile, 'w')
    file.write('[hostexec]\n')
    for ip, name in zip(server_ips, server_namekey):
        file.write(f'{ip} namekey={name} ipserver={ip} serverapp={serverlocal}\n')
    file.close()
    var_ansible_multi(user, groups, mail)
    content={ "tagsexc": ['adduser-host', 'permissions'], "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
    r=requests.post(url_api_ansible_mul, json=content, headers=headers, verify=False)
    result=r.json()
    if result['status']==0:
        for item in accessuser:
            server_id = item["serverid"]
            apiservers = requests.get(urlservers+'/'+str(server_id), headers=headers, verify=False).json()
            tipeserver=item['tipe']
            if tipeserver=='server':
                ipserver=apiservers['ipadmin']
                namekey=apiservers['namekey']
                filekey=namekey+'_'+ipserver+'.pem'
                insertQuery = Access('server',filekey,'N/A',server,user,server_id,iduser)
                db.session.add(insertQuery)
                db.session.commit()
                logging.info('Nuevo usuario: '+user+' creado en el server'+ipserver)
                flash('Nuevo usuario: '+user+' creado en el server'+ipserver, 'ok')
        return redirect(url_for('users', estado='ok'))
    else:
        flash('Error al intentar Verifica la causa', 'error')
        logging.info('Erro al generar acceso a usuario '+user+' en el server '+ipserver+' Messaje de error: '+str(result['status']))
        return redirect(url_for('users', estado='error'))

def update_ip_access():
    content={ "tagsexc": ['update_ip'], "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
    r=requests.post(url_api_ansible_mul, json=content, headers=headers, verify=False)
    result=r.json()
    if result['status']==0:
        flash('Los accesos fueron generados correctamente', 'ok')
    else:
        flash('Error verifica la conexión o contacta al administrador', 'error')
        return redirect(url_for('servers'))
    return result['status']

def update_data_access():
    content={ "tagsexc": ['update-data'], "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
    r=requests.post(url_api_ansible_mul, json=content, headers=headers, verify=False)
    result=r.json()
    if result['status']==0:
        flash('Los accesos fueron generados correctamente', 'ok')
    else:
        flash('Error verifica la conexión o contacta al administrador', 'error')
        return redirect(url_for('servers'))
    return result['status']

def genresources():
    content={ "tagsexc": ['update-resources'], "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
    r=requests.post(url_api_ansible_mul, json=content, headers=headers, verify=False)
    result=r.json()
    if result['status']==0:
        flash('Los accesos fueron generados correctamente', 'ok')
    else:
        flash('Error verifica la conexión o contacta al administrador', 'error')
        return redirect(url_for('servers'))

def inventory_ansible():
    logging.info('creating YML file inventory')
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    ipbastion=apibastion['ip']
    logging.info('creating YML file inventory'+ipbastion)
    file = open(inventoryfile,'w')
    file.write('[hostexec]\n')
    file.write(ipbastion+'\n')
    file.write('\n')
    file.close()

def var_ansible(user, grupo, email, ipserver, namekey):
    logging.info('creating YML file vars')
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    ipbastion=apibastion['ip']
    dnsbastion=apibastion['dns']
    file = open('app/ansible/roles/manageCustomUsers/vars/main.yml','w')
    file.write('---\n')
    file.write('# vars file for roles/addCustomUsers\n')
    file.write('\n')
    file.write('usuario: "'+user+'"\n')
    file.write('grupo: "'+grupo+'"\n')
    file.write('email: "'+email+', '+reception_mails+'"\n')
    file.write('dirfile: "'+dirfilepem+'/'+user+'"\n')
    file.write('dirgoogle: "'+dirfileqr+'"\n')
    file.write('\n')
    file.write('# SERVER ACCESS\n')
    file.write('\n')
    file.write('namekey: "'+namekey+'"\n')
    file.write('ipserver: "'+ipserver+'"\n')
    file.write('\n')
    file.write('# vars config smtp server\n')
    file.write('\n')
    file.write('host_smtp: "'+host_smtp+'"\n')
    file.write('port_smtp: "'+str(port_smtp)+'"\n')
    file.write('user_smtp: "'+user_smtp+'"\n')
    file.write('pass_smtp: "'+pass_smtp+'"\n')
    file.write('\n')
    file.write('# Config bastion host\n')
    file.write('ipbastion: "'+ipbastion+'"\n')
    file.write('dnsbastion: "'+dnsbastion+'"\n')
    file.write('\n')
    file.write('serverapp: '+serverlocal+'\n')
    file.write('\n')
    file.write('admin_user: '+userans+'\n')
    file.close()

def var_ansible_multi_user(ipserver, namekey):
    logging.info('creating YML file vars')
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    ipbastion=apibastion['ip']
    dnsbastion=apibastion['dns']
    file = open('app/ansible/roles/manageCustomUsers/vars/main.yml','w')
    file.write('---\n')
    file.write('# vars file for roles/addCustomUsers\n')
    file.write('dirfile: "'+dirfilepem+'/"\n')
    file.write('dirgoogle: "'+dirfileqr+'"\n')
    file.write('\n')
    file.write('# SERVER ACCESS\n')
    file.write('\n')
    file.write('namekey: "'+namekey+'"\n')
    file.write('ipserver: "'+ipserver+'"\n')
    file.write('\n')
    file.write('# vars config smtp server\n')
    file.write('\n')
    file.write('host_smtp: "'+host_smtp+'"\n')
    file.write('port_smtp: "'+str(port_smtp)+'"\n')
    file.write('user_smtp: "'+user_smtp+'"\n')
    file.write('pass_smtp: "'+pass_smtp+'"\n')
    file.write('\n')
    file.write('# Config bastion host\n')
    file.write('ipbastion: "'+ipbastion+'"\n')
    file.write('dnsbastion: "'+dnsbastion+'"\n')
    file.write('\n')
    file.write('serverapp: '+serverlocal+'\n')
    file.write('\n')
    file.write('admin_user: '+userans+'\n')
    file.close()

def var_ansible_multi(user, grupo, email):
    logging.info('creating YML file vars')
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    ipbastion=apibastion['ip']
    dnsbastion=apibastion['dns']
    file = open('app/ansible/roles/manageCustomUsers/vars/main.yml','w')
    file.write('---\n')
    file.write('# vars file for roles/addCustomUsers\n')
    file.write('\n')
    file.write('usuario: "'+user+'"\n')
    file.write('grupo: "'+grupo+'"\n')
    file.write('email: "'+email+', '+reception_mails+'"\n')
    file.write('dirfile: "'+dirfilepem+'/'+user+'"\n')
    file.write('dirgoogle: "'+dirfileqr+'"\n')
    file.write('\n')
    file.write('# SERVER ACCESS\n')
    file.write('\n')
    file.write('# vars config smtp server\n')
    file.write('\n')
    file.write('host_smtp: "'+host_smtp+'"\n')
    file.write('port_smtp: "'+str(port_smtp)+'"\n')
    file.write('user_smtp: "'+user_smtp+'"\n')
    file.write('pass_smtp: "'+pass_smtp+'"\n')
    file.write('\n')
    file.write('# Config bastion host\n')
    file.write('ipbastion: "'+ipbastion+'"\n')
    file.write('dnsbastion: "'+dnsbastion+'"\n')
    file.write('\n')
    file.write('serverappp: '+serverlocal+'\n')
    file.write('\n')
    file.write('admin_user: '+userans+'\n')
    file.close()
######################## API ##################################

@app.route('/core/v1.0/access')
def apiaccess():
    query = db.session.query(Access).all()
    art=[]
    for res in query:
        dict ={'tipe': res.tipe, 'keypair': res.keypair, 'keyqr': res.keyqr, 'serverid': res.serverid,
        'userid':res.userid, 'server': res.server, 'user':res.user, 'id':res.id }
        art.append(dict)
    db.session.commit()
    return jsonify(art), 200

@app.route('/core/v1.0/access/<id>')
def apiaccessfilt(id):
    query = db.session.query(Access).filter(Access.id.in_([id])).all()
    for res in query:
        data = { 'tipe': res.tipe, 'keypair': res.keypair, 'keyqr': res.keyqr, 'server': res.server, 'user':res.user, 'serverid': res.serverid, 'userid':res.userid, 'id':res.id }
    db.session.commit()
    return jsonify(data), 200

@app.route('/core/v1.0/access/user/<id>')
def useraccess(id):
    query = db.session.query(Access).filter(Access.userid==id).all()
    art=[]
    for res in query:
        data = { 'tipe': res.tipe, 'keypair': res.keypair, 'keyqr': res.keyqr, 'server': res.server, 'user':res.user, 'serverid': res.serverid, 'userid':res.userid, 'id':res.id }
        art.append(data)
    db.session.commit()
    return jsonify(art), 200

@app.route('/core/v1.0/access/servers/<id>')
def servaccess(id):
    query = db.session.query(Access).filter(Access.serverid==id).all()
    art=[]
    for res in query:
        data = { 'tipe': res.tipe, 'keypair': res.keypair, 'keyqr': res.keyqr, 'server': res.server, 'user':res.user, 'serverid': res.serverid, 'userid':res.userid, 'id':res.id }
        art.append(data)
    db.session.commit()
    return jsonify(art), 200

@app.route('/core/v1.0/bastion')
def apibastion():
    query = db.session.query(Bastion).all()
    for res in query:
        data = {'dns': res.dns, 'bastion': res.bastion, 'idserver': res.idbastion, 'location': res.location, 'ip':res.ip, 'id':res.id }
    db.session.commit()
    return jsonify(data), 200

@app.route('/core/v1.0/ansible', methods=['POST'])
def api_playbook():
    content=request.get_json(force=True)
    tagsexc=content['tagsexc']
    ipmanage=content['ipmanage']
    keyfile=content['fileprivatekey']
    play=content['play']
    passwd=content['passwd']
    user=content['user']
    inventory=content['inventory']
    logging.info('runnig ansible-playbook ' + ', '.join(tagsexc) + ' ' + ipmanage)
    file = open(inventory,'w')
    file.write('[hostexec]\n')
    file.write(ipmanage)
    file.close()
    loader = DataLoader()
    if passwd:
        context.CLIARGS = ImmutableDict(tags=tagsexc, listtags=False, listtasks=False, listhosts=False, syntax=False, connection='ssh',
                        module_path=None, forks=10, remote_user=user, private_key_file=None,
                        ssh_common_args=None, ssh_extra_args=None, sftp_extra_args=None, scp_extra_args=None, become=True,
                        become_method='sudo', become_user='root', verbosity=True, check=False, start_at_task=None,
                        extra_vars={'ansible_ssh_user='+user+'', 'ansible_ssh_pass='+passwd+'', 'ansible_become_pass='+passwd+''})
    else:
        context.CLIARGS = ImmutableDict(tags=tagsexc, listtags=False, listtasks=False, listhosts=False, syntax=False, connection='ssh',
                        module_path=None, forks=10, remote_user=user, private_key_file=None,
                        ssh_common_args=None, ssh_extra_args=None, sftp_extra_args=None, scp_extra_args=None, become=True,
                        become_method='sudo', become_user='root', verbosity=True, check=False, start_at_task=None,
                        extra_vars={'ansible_ssh_user='+user+'', 'ansible_ssh_private_key_file='+keyfile+''})
    inventory = InventoryManager(loader=loader, sources=(inventory))
    variable_manager = VariableManager(loader=loader, inventory=inventory, version_info=CLI.version_info(gitinfo=False))
    pbex = PlaybookExecutor(playbooks=[play], inventory=inventory, variable_manager=variable_manager, loader=loader, passwords={})
    results = pbex.run()
    db.session.commit()
    return jsonify({'status':results}), 200

@app.route('/core/v2.0/ansible/multi', methods=['POST'])
def api_playbook_mul():
    content=request.get_json(force=True)
    tagsexc=content['tagsexc']
    keyfile=content['fileprivatekey']
    play=content['play']
    passwd=content['passwd']
    user=content['user']
    inventory=content['inventory']
    loader = DataLoader()
    if passwd:
        context.CLIARGS = ImmutableDict(tags=tagsexc, listtags=False, listtasks=False, listhosts=False, syntax=False, connection='ssh',
                        module_path=None, forks=10, remote_user=user, private_key_file=None,
                        ssh_common_args=None, ssh_extra_args=None, sftp_extra_args=None, scp_extra_args=None, become=True,
                        become_method='sudo', become_user='root', verbosity=True, check=False, start_at_task=None,
                        extra_vars={'ansible_ssh_user='+user+'', 'ansible_ssh_pass='+passwd+'', 'ansible_become_pass='+passwd+''})
    else:
        context.CLIARGS = ImmutableDict(tags=tagsexc, listtags=False, listtasks=False, listhosts=False, syntax=False, connection='ssh',
                        module_path=None, forks=10, remote_user=user, private_key_file=None,
                        ssh_common_args=None, ssh_extra_args=None, sftp_extra_args=None, scp_extra_args=None, become=True,
                        become_method='sudo', become_user='root', verbosity=True, check=False, start_at_task=None,
                        extra_vars={'ansible_ssh_user='+user+'', 'ansible_ssh_private_key_file='+keyfile+''})
    inventory = InventoryManager(loader=loader, sources=(inventory))
    variable_manager = VariableManager(loader=loader, inventory=inventory, version_info=CLI.version_info(gitinfo=False))
    pbex = PlaybookExecutor(playbooks=[play], inventory=inventory, variable_manager=variable_manager, loader=loader, passwords={})
    results = pbex.run()
    db.session.commit()
    return jsonify({'status':results}), 200

@app.route('/get_log', methods=['GET'])
def get_log():
    log_file = os.path.join(app.root_path, rutalogs)
    with open(log_file, 'r') as file:
        #log_text = file.read()
        lines = file.readlines()
        last_100_lines = lines[-100:]
        log_text = ''.join(last_100_lines)
    return log_text