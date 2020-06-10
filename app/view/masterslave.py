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
        
######################################### install master and Slaves servers ###################3333
@app.route('/masterslaves')
@login_required
def masterslaves():
    master = db.session.query(Master).filter().first()
    statuslave = ''
    statusmaster = ''
    statusacl = ''
    exist=True
    if request.args.get('statusmaster'):
        statusmaster=request.args.get('statusmaster')
    elif request.args.get('statuslave'):
        statuslave=request.args.get('statuslave')
    elif request.args.get('statusacl'):
        statusacl = request.args.get('statusacl')
    if master:
        exist=False
    slaves = db.session.query(Slaves).filter().all()
    acls = db.session.query(Acls).filter().all()
    db.session.commit()
    user = current_user.username
    return render_template('master-slaves.html', ipslaves=slaves, master=master, user=user, exist=exist, acls=acls, statuslave=statuslave, statusmaster=statusmaster, statusacl=statusacl)

@app.route('/core/addmaster', methods=['POST'])
@login_required
def addmaster():
    master = str(request.form['master'])
    masterserver = db.session.query(Master).filter(Master.ipmaster == master).first()
    slaveserver = db.session.query(Slaves).filter(Slaves.ipslave == master).first()
    statusmaster=''
    if masterserver:
        validate='You have already this server master'
        return redirect(url_for('config', statusmaster=validate))
    elif slaveserver:
        validate='This server is slave'
        return redirect(url_for('config', statusmaster=validate))
    user = str(request.form['user'])
    password = str(request.form['password'])
    insertQuery = Master(master,user,password)
    db.session.add(insertQuery)
    db.session.commit()
    logging.info('Add master '+master+' '+user)
    return redirect(url_for('masterslaves'))

@app.route('/core/deletemaster', methods=['POST'])
@login_required
def deletemaster():
    if request.form['delete_button']:
        idf = int(request.form['delete_button'])
        db.session.query(Master).filter(Master.id == idf).delete(synchronize_session=False)
        db.session.commit()
        return redirect(url_for('masterslaves'))

@app.route('/core/addslave', methods=['POST'])
@login_required
def addslave():
    slave = str(request.form['slave'])
    master = db.session.query(Master).filter(Master.ipmaster == slave).first()
    slaveserver = db.session.query(Slaves).filter(Slaves.ipslave == slave).first()
    validate=''
    if master:
        validate='This server is master'
        return redirect(url_for('masterslaves', statuslave=validate))
    elif slaveserver:
        validate='You have already added this server'
        return redirect(url_for('masterslaves', statuslave=validate))
    user = str(request.form['user'])
    password = str(request.form['password'])
    insertQuery = Slaves(slave,user,password)
    db.session.add(insertQuery)
    db.session.commit()
    logging.info('Add slave '+slave+' '+user)
    return redirect(url_for('config'))

@app.route('/core/deleteslave', methods=['POST'])
@login_required
def deleteslave():
    if request.form['delete_button']:
        idf = int(request.form['delete_button'])
        db.session.query(Slaves).filter(Slaves.id == idf).delete(synchronize_session=False)
        db.session.commit()
        return redirect(url_for('masterslaves'))

@app.route('/core/installdns', methods=['POST'])
@login_required
def installdns():
    tagsexc='install'
    master = db.session.query(Master).filter().first()
    ipmanage= master.ipmaster
    passwd= master.password
    user= master.user
    db.session.commit()
    install_dns_playbook(tagsexc, ipmanage, passwd, user)
    slaves = db.session.query(Slaves).filter().all()
    if slaves:
        for slave in slaves:
            ipmanage= slave.ipslave
            passwd= slave.password
            user= slave.user
            install_dns_playbook(tagsexc, ipmanage, passwd, user)
            db.session.commit()
    return redirect(url_for('masterslaves'))

########################################## API Ansible-Playbooks ###################################################

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