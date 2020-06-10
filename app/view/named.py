from flask import render_template, redirect, url_for, request, jsonify, session
import os, requests, json, sys

# APP MVC
from app import app, cf, login_manager, db
from app.models import Users, Hosting, Domain, Register, Master, Slaves, Acls, Forwards

# MAIL
import email, smtplib, ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

#packages ansible
from ansible import context
from ansible.cli import CLI
from ansible.module_utils.common.collections import ImmutableDict
from ansible.executor.playbook_executor import PlaybookExecutor
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager

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
logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG)
logging.info('Comenzando la aplicacion...')
        
####################### named #############################

@app.route('/named')
@login_required
def named():
    master = db.session.query(Master).filter().first()
    statusacl = ''
    statusforward = ''
    exist=True
    if request.args.get('statusacl'):
        statusacl = request.args.get('statusacl')
    elif request.args.get('statusforward'):
        statusforward = request.args.get('statusforward')
    elif master:
        exist=False
    acls = db.session.query(Acls).filter().all()
    forwards = db.session.query(Forwards).filter().all()
    db.session.commit()
    user = current_user.username
    return render_template('named.html', forwards=forwards, master=master, user=user, exist=exist, acls=acls, statusacl=statusacl, statusforward=statusforward)

@app.route('/core/addforward', methods=['POST'])
@login_required
def addforward():
    forward = str(request.form['forward'])
    forwards = db.session.query(Forwards).filter(Forwards.ipforward == forward).first()
    validate=''
    if forwards:
        validate='You have already added this forward'
        return redirect(url_for('named', statusforward=validate))
    insertQuery = Forwards(forward)
    db.session.add(insertQuery)
    db.session.commit()
    logging.info('Add forward '+forward)
    return redirect(url_for('named'))

@app.route('/core/forwadcommit', methods=['POST'])
@login_required
def forwadcommit():
    slaves = db.session.query(Slaves).filter().all()
    if slaves:
        for slave in slaves:
            dif=slave.id
            nameconf_slave(dif)
            tagsexc='allowqueryslave'
            ipmanage= slave.ipslave
            passwd= slave.password
            user= slave.user
            install_dns_playbook(tagsexc, ipmanage, passwd, user)
    tagsexc='allowquerymaster'
    master = db.session.query(Master).filter().first()
    ipmanage= master.ipmaster
    passwd= master.password
    user= master.user
    nameconf_master()
    install_dns_playbook(tagsexc, ipmanage, passwd, user)
    db.session.commit()
    return redirect(url_for('named')) 

@app.route('/core/deleteforward', methods=['POST'])
@login_required
def deleteforward():
    if request.form['delete_button']:
        idf = int(request.form['delete_button'])
        db.session.query(Forwards).filter(Forwards.id == idf).delete(synchronize_session=False)
        db.session.commit()
        return redirect(url_for('named'))

@app.route('/core/addacl', methods=['POST'])
@login_required
def addacl():
    acl = str(request.form['acl'])
    acls = db.session.query(Acls).filter(Acls.ipacl == acl).first()
    validate=''
    if acls:
        validate='You have already added this acl'
        return redirect(url_for('named', statusacl=validate))
    insertQuery = Acls(acl)
    db.session.add(insertQuery)
    db.session.commit()
    logging.info('Add acl '+acl)
    return redirect(url_for('named'))

@app.route('/core/allowquery', methods=['POST'])
@login_required
def allowquery():
    slaves = db.session.query(Slaves).filter().all()
    if slaves:
        for slave in slaves:
            dif=slave.id
            nameconf_slave(dif)
            tagsexc='allowqueryslave'
            ipmanage= slave.ipslave
            passwd= slave.password
            user= slave.user
            install_dns_playbook(tagsexc, ipmanage, passwd, user)
    tagsexc='allowquerymaster'
    master = db.session.query(Master).filter().first()
    ipmanage= master.ipmaster
    passwd= master.password
    user= master.user
    nameconf_master()
    install_dns_playbook(tagsexc, ipmanage, passwd, user)
    db.session.commit()
    return redirect(url_for('named'))

@app.route('/core/deleteacl', methods=['POST'])
@login_required
def deleteacl():
    if request.form['delete_button']:
        idf = int(request.form['delete_button'])
        db.session.query(Acls).filter(Acls.id == idf).delete(synchronize_session=False)
        db.session.commit()
        return redirect(url_for('named'))

########################################### API Ansible-Playbooks ###################################################

def install_dns_playbook(tagsexc, ipmanage, passwd, user):
    logging.info('runnig ansible-playbook install dns')
    file = open('app/ansible/hosts','w')
    file.write('[dnsservers]\n')
    file.write(ipmanage)
    file.close()
    loader = DataLoader()
    context.CLIARGS = ImmutableDict(tags={tagsexc}, listtags=False, listtasks=False, listhosts=False, syntax=False, connection='ssh',
                    module_path=None, forks=10, remote_user='ansadmin', private_key_file=None,
                    ssh_common_args=None, ssh_extra_args=None, sftp_extra_args=None, scp_extra_args=None, become=True,
                    become_method='sudo', become_user='root', verbosity=True, check=False, start_at_task=None,
                    extra_vars={'ansible_ssh_user='+user+'', 'ansible_ssh_pass='+passwd+'', 'ansible_become_pass='+passwd+''})
    inventory = InventoryManager(loader=loader, sources=('app/ansible/hosts'))
    variable_manager = VariableManager(loader=loader, inventory=inventory, version_info=CLI.version_info(gitinfo=False))
    pbex = PlaybookExecutor(playbooks=['app/ansible/webadmindns.yml'], inventory=inventory, variable_manager=variable_manager, loader=loader, passwords={})
    results = pbex.run()
    db.session.commit() 

####################################### File config named.conf #############################################################

def nameconf_master():
    file = open('app/ansible/roles/webadmindns/templates/named.conf.master.j2','w')
    file.write('acl "allowed" {\n')
    acls = db.session.query(Acls).filter().all()
    for acl in acls:
        file.write('        '+acl.ipacl+';\n')
    file.write('};\n')
    file.write('acl "slaves" {\n')
    slaves = db.session.query(Slaves).filter().all()
    for slave in slaves:
        file.write('        '+slave.ipslave+';\n')
    file.write('};\n')
    file.write('options {\n')
    file.write('        directory "/etc/named";\n')
    master = db.session.query(Master).filter().first()
    file.write('        listen-on port 53 { '+master.ipmaster+'; 127.0.0.1; };\n')
    file.write('        listen-on-v6 { none; };\n')
    file.write('        allow-query  { allowed; 127.0.0.0/8; };\n')
    forwards = db.session.query(Forwards).filter().all()
    if forwards:
        file.write('        forwarders {\n')
        for forward in forwards:
            file.write('                '+forward.ipforward+'; \n')
        file.write('        };\n')
    else:
        file.write('        recursion no;\n')   
    file.write('        version "No disponible";\n')
    file.write('        check-names master ignore;\n')
    file.write('        check-names response ignore;\n')
    file.write('};\n')
    url = cf.APIHOSETD
    headers = {'Content-type': 'application/json'}
    hosting = requests.get(url, headers=headers, verify=False).json()
    for zone in hosting:
        file.write('zone "'+zone['zones']+'" {\n') 
        file.write('        type master;\n')
        file.write('        file "/etc/named/zones/'+zone['zones']+'.zone";\n')
        file.write('        allow-transfer { slaves; };\n')
        file.write('};\n')
    db.session.commit()
    file.close() 

def nameconf_slave(id):
    file = open('app/ansible/roles/webadmindns/templates/named.conf.slave.j2','w')
    file.write('acl "allowed" {\n')
    acls = db.session.query(Acls).filter().all()
    for acl in acls:
        file.write('        '+acl.ipacl+';\n')
    file.write('};\n')
    file.write('options {\n')
    file.write('        directory "/etc/named";\n')
    slave = db.session.query(Slaves).filter(Slaves.id == id).first()
    file.write('        listen-on port 53 { '+slave.ipslave+'; 127.0.0.1; };\n')
    file.write('        listen-on-v6 { none; };\n')
    file.write('        allow-query  { allowed; 127.0.0.0/8; };\n')
    forwards = db.session.query(Forwards).filter().all()
    if forwards:
        file.write('        forwarders {\n')
        for forward in forwards:
            file.write('                '+forward.ipforward+'; \n')
        file.write('        };\n')
    else:
        file.write('        recursion no;\n')    
    file.write('        version "No disponible";\n')
    file.write('};\n')
    url = cf.APIHOSETD
    headers = {'Content-type': 'application/json'}
    hosting = requests.get(url, headers=headers, verify=False).json()
    master = db.session.query(Master).filter().first()
    for zone in hosting:
        file.write('zone "'+zone['zones']+'" {\n') 
        file.write('        type slave;\n')
        file.write('        file "/etc/named/cache/'+zone['zones']+'.zone";\n')
        file.write('        masters { '+master.ipmaster+'; };\n')
        file.write('};\n')
    db.session.commit()
    file.close()