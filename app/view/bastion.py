from flask import render_template, redirect, url_for, request, jsonify, session, Blueprint, flash
import os, requests, json, sys, re, io, base64

from .home import validatebastion
from .permissions import sudoers_delete_policies, sudoers_delete_groups, sudoers_policies, sudoers_groups, api_playbook_role

# APP MVC
from app import app, cf, login_manager, db
from app.models import Servers, Users, Access, Bastion, UGRelation, Policy, UGPolicies, Groups, GSRelation

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
dirfiles=cf.DIRFILES
reception_mails=cf.RECIVE_MAILS
serverlocal=cf.SERVER
rutalogs = cf.RUTALOG
urlaccessuser = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/core/v1.0/access/user'
urlapigroups = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/core/v1.0/groups'
urlugrelation = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/core/v1.0/ugrelation'

####################### Endpoints #############################

@app.route('/bastion', methods=['GET'], defaults={"page_num": 1})
@app.route('/bastion/<int:page_num>', methods=['GET'])
@login_required
def bastion(page_num):
    getbastion = db.session.query(Bastion).first()
    ipbastion = getbastion.ip
    filteruser=request.args.get('filteruser')
    filterhost=request.args.get('filterhost')
    filterserver=request.args.get('findserver')
    filterbastion = request.args.get('createaccess')
    if filterbastion is None or filterbastion == False:
        filterbastion=False
    else:
        filterbastion=True
    accessserver = db.session.query(Access).filter(Access.tipe=='server')
    apibastion=''
    nameuser=False
    apiaccess=db.session.query(Access).paginate(per_page=20, page=page_num, error_out=True)
    if filteruser:
        queryuser = db.session.query(Users).filter(Users.id==int(filteruser)).first()
        nameuser=queryuser.username
        logging.info('Filter user on page bastion')
        apiaccess=db.session.query(Access).filter(Access.userid==int(filteruser)).paginate(per_page=20, page=page_num, error_out=True)
        if filterserver:
            search = "%{}%".format(filterserver)
            apiaccess=db.session.query(Access).filter(and_(Access.userid==int(filteruser), Access.keypair.like(search))).paginate(per_page=10, page=page_num, error_out=True)
            filterserver=True
    if filterhost:
        logging.info('Filter host on page bastion')
        apiaccess=db.session.query(Access).filter(Access.serverid==int(filterhost)).paginate(per_page=10, page=page_num, error_out=True)
        apigroups = requests.get(urlservers+'/'+str(filterhost), headers=headers, verify=False).json()
        filterhost = apigroups['namekey']
    apiservers = requests.get(urlservers, headers=headers, verify=False).json()
    apiusers = requests.get(urlusers, headers=headers, verify=False).json()
    logging.info('Access page Bastion')
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    return render_template('bastion.html', ipbastion=ipbastion, filteruser=filteruser,filterhost=filterhost, validatebastion=validatebastion(), user=user, nameuser=nameuser, apiservers=apiservers, apiusers=apiusers, apibastion=apibastion, data=apiaccess, mail=mail, accessserver=accessserver, filterbastion=filterbastion)

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
        
def bastionclient(iduser, user, email):
    try:
        apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
        idserver = apibastion.get('idserver')
        
        if idserver is None:
            flash('No se pudo obtener información del servidor', 'error')
            logging.warning('No se pudo obtener información del servidor para ' + user)
            return False  # Indica que la operación falló
            
        apiservers = requests.get(f'{urlservers}/{idserver}', headers=headers, verify=False).json()
        server = apiservers.get('hostname')
        ipserver = apiservers.get('ipadmin')
        namekey = apiservers.get('namekey')
        filekey = f"{namekey}_{user}.pem"
        fileqrm = f"{namekey}_{user}.txt"

        queryuser = Access.query.filter(and_(Access.server == server, Access.user == user, Access.tipe == 'client')).first()
        if queryuser:
            flash('Ya existe este acceso', 'error')
            logging.warning('Ya tiene acceso a bastion ' + user)
            return False  # Indica que la operación falló
            
        var_ansible(user, '', email, ipserver, namekey)
        
        content = {
            "tagsexc": ['adduser-mfa'],
            "ipmanage": ipserver,
            "fileprivatekey": fileprivatekey,
            "passwd": "",
            "user": userans,
            "inventory": inventoryfile,
            "play": playbookyml
        }
        
        r = requests.post(url_api_ansible, json=content, headers=headers, verify=False)
        result = r.json()
        
        if result['status'] == 0:
            insertQuery = Access('client', filekey, fileqrm, server, user, idserver, iduser)
            db.session.add(insertQuery)
            db.session.commit()
            logging.info('se crea nuevo usuario: ' + user)
            flash('Nuevo usuario creado ' + user, 'ok')
        else:
            flash('Error al intentar. Verifica la causa', 'error')
            logging.info(f'Error al generar client-bastion {user} {result["status"]}')
            return False  # Indica que la operación falló
        
        return True  # Indica que la operación tuvo éxito
    except Exception as e:
        flash('Ocurrió un error inesperado. Verifica la causa', 'error')
        logging.error('Error inesperado: ' + str(e))
        return False  # Indica que la operación falló

@app.route('/combastion', methods=['POST'])
@login_required
def combastion():
    idaccess = request.form.get('valoresSeleccionados')
    elementos = idaccess.split(',')
    idaccessserver = [int(elemento) for elemento in elementos]
    getugpolicies = db.session.query(UGPolicies).all()
    for accessid in idaccessserver:
        getpolicyids_list = []
        listpolicy = []
        apiaccess = requests.get(urlaccess+'/'+str(accessid), headers=headers, verify=False).json()
        iduser = apiaccess['userid']
        idserver = apiaccess['serverid']
        apiusers = requests.get(urlusers+'/'+str(iduser), headers=headers, verify=False).json()
        apiservers = requests.get(urlservers+'/'+str(idserver), headers=headers, verify=False).json()
        ipserver=apiservers['ipadmin']
        server=apiservers['hostname']
        user=apiusers['username']
        email=apiusers['email']
        namekey=apiservers['namekey']
        filekey=namekey+'_'+ipserver+'.pem'
        getidsgroups = []
        getgsrelation = db.session.query(GSRelation).all()
        getugrelation = db.session.query(UGRelation).all()
        getgroup = db.session.query(Groups).all()
        getpolicies = db.session.query(Policy).all()
        for res in getgsrelation:
            if str(res.idserver) == str(idserver):
                getidsgroups.append(res.idug)
        for idspolicies in getugpolicies:
            for idgroup in getidsgroups:
                if idspolicies.type_ug == "group" and idspolicies.id_ug == idgroup:
                    getpolicyids_list.append(idspolicies.id_policy)
        getpolicyids = list(set(getpolicyids_list))
        for idspoli in getpolicies:
            for ids in getpolicyids:
                if idspoli.id == ids:
                    listpolicy.append({idspoli.name: idspoli.policy})
        sudoers_delete_policies()
        namepolicies=[]
        for item in listpolicy:
            for key, value in item.items():
                namepolicies.append(key)
                sudoers_policies(key,value)
        group_policies = {}
        # Itera a través de los grupos en getidsgroups
        for idgroup in getidsgroups:
            # Inicializa una lista vacía para las políticas de este grupo
            group_policies[idgroup] = []

            # Itera a través de las políticas y encuentra las que corresponden a este grupo
            for ugpolicy in getugpolicies:
                if str(ugpolicy.id_ug) == str(idgroup) and ugpolicy.type_ug == "group":
                    for getpolicy in getpolicies:
                        if str(getpolicy.id) == str(ugpolicy.id_policy):
                            group_policies[idgroup].append(getpolicy.name)
        sudoers_delete_groups()
        # Ahora, imprime la información de los grupos con sus políticas
        for idgroup, policies in group_policies.items():
            group_name = None
            for res in getgroup:
                if str(res.id) == str(idgroup):
                    group_name = res.name
            if group_name and policies:
                formatted_policies = ", ".join(policies)
                sudoers_groups(group_name,formatted_policies)
        getusergroups = []
        getnamesgroups = []
        for res in getugrelation:
            if res.id_user == int(iduser):
                getusergroups.append(res.id_group)
        for getidg in getusergroups:
            apigroups = requests.get(urlapigroups+'/'+str(getidg), headers=headers, verify=False).json()
            getnamesgroups.append(apigroups['name'])
        inventory_ansible()
        var_ansible(user, getnamesgroups, email, ipserver, namekey)
        content={ "tagsexc": ['adduser-host', 'permissions', 'role-sudo'], "ipmanage": ipserver, "fileprivatekey":fileprivatekey, "passwd": "", "user": userans, "inventory":inventoryfile, "play":playbookyml }
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
    namekey=apiservers['namekey']
    var_ansible(user, [], email, ipserver, namekey)
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
        getgroup = requests.get(urlugrelation, headers=headers, verify=False).json()
        getidsgroups = []
        getnamesgroups = []
        for res in getgroup:
            if res['id_user'] == int(iduser):
                getidsgroups.append(res['id_group'])
        for getidg in getidsgroups:
            apigroups = requests.get(urlapigroups+'/'+str(getidg), headers=headers, verify=False).json()
            getnamesgroups.append(apigroups['name'])

        namekey=apiservers['namekey']

        file = open(inventoryfile,'w') # Archivo de inventory de ansible
        file.write('[hostexec]\n')
        file.write(str(ipserver)+'\n')
        file.write('\n')
        file.close()

        var_ansible(user, getnamesgroups, email, ipserver, namekey)
        
        role = ['report']
        results, status_code = api_playbook_role(role)
        if status_code == 200:
            if results == 4:
                flash(f'Error al intentar conectar al servidor', 'error')
            elif results == 0:
                flash(f'Se genera correctamente', 'ok')
            elif results == 2:
                flash(f'Tienes que revisar el servidor hay problemas con el playbook', 'error')
        else:
            flash('Error al obtener la respuesta del servidor', 'error')

        input_file = dirfiles+'/audit/audit_'+user+'_'+ipserver+'.txt'
        output_file = dirfiles+'/audit/audit_filt_'+user+'_'+ipserver+'.txt'
        outfilter = dirfiles+'/audit/audit_report_'+user+'_'+ipserver+'.txt'
        parse_audit_logs_from_file(input_file, output_file)
        generate_audit_report(output_file, outfilter)

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

def parse_audit_logs_from_file(record, out_file):
    user_logs = {}
    current_user = None

    with open(record, 'r') as file:
        log_sections = file.read().split('----\n')

    with open(out_file, "w") as report_file:  # Abre el archivo una vez para escritura
        for log_section in log_sections:
            log_lines = log_section.strip().split('\n')
            for i in range(len(log_lines)):
                log_lines[i] = re.sub(r'"|\'', '', log_lines[i])
            result = []
            listreport = {}
            # Extraer el tiempo completo de la primera línea
            time_line = log_lines[0]
            time_match = re.search(r'time->(.+)', time_line)
            if time_match:
                log_entry = {'time': time_match.group(1)}
            for line in log_lines[1:]:
                log_entry = log_entry.copy()
                # Extraer el tipo
                type_match = re.search(r'type=(\S+)', line)
                if type_match:
                    log_entry['type'] = type_match.group(1)
                # Extraer el mensaje
                msg_match = re.search(r'msg=(.+)', line)
                if msg_match:
                    log_entry['msg'] = msg_match.group(1)
                result.append(log_entry)
            for entry in result:
                report_file.write(str(entry) + '\n')

def generate_audit_report(records_file, out_file):
    with open(records_file, 'r') as file:
        log_sections = file.readlines()

    with io.open(out_file, "w", encoding="utf-8") as report_file:
        for log_section in log_sections:
            log_entry = eval(log_section)  # Convierte la cadena a un diccionario
            report_file.write(f"Fecha y hora: {log_entry.get('time', 'N/A')}\n")
            report_file.write(f"Tipo: {log_entry.get('type', 'N/A')}\n")
            msg = log_entry.get('msg', 'N/A')
            report_file.write(f"Mensaje: {msg}\n")
            report_file.write("Descripción:\n")
            res_match = re.search(r'res=(\w+)', msg)
            res = res_match.group(1) if res_match else 'N/A'
            report_file.write(f"Resultado: {res}\n")
            
            # Agregar "Comando ejecutado" para USER_CMD
            if 'USER_CMD' in log_entry.get('type', ''):
                cmd_match = re.search(r'cmd=([\w\d]+)', msg)  # Cambio la expresión regular para capturar solo palabras y números
                cmd_encoded = cmd_match.group(1) if cmd_match else 'N/A'
                try:
                    cmd_decoded = base64.b64decode(cmd_encoded).decode("utf-8")
                except:
                    cmd_decoded = 'No se pudo decodificar'
                report_file.write(f"Comando ejecutado: {cmd_decoded}\n")
            
            report_file.write("\n")

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
    getgroup = requests.get(urlugrelation, headers=headers, verify=False).json()
    getidsgroups = []
    getnamesgroups = []
    for res in getgroup:
        if res['id_user'] == int(iduser):
            getidsgroups.append(res['id_group'])
    for getidg in getidsgroups:
        apigroups = requests.get(urlapigroups+'/'+str(getidg), headers=headers, verify=False).json()
        getnamesgroups.append(apigroups['name'])
    namekey=apiservers['namekey']
    ipserver=apiservers['ipadmin']
    filekey=namekey+'_'+ipserver+'.pem'
    inventory_ansible()
    var_ansible(user, getnamesgroups, email, ipserver, namekey)
    queryuser =  Access.query.filter(and_(Access.server==server, Access.user==user, Access.tipe=='server' )).first()
    if queryuser:
        flash('Ya existe este acceso', 'error')
        logging.warning('Ya tiene acceso a bastion '+user)
        return redirect(url_for('bastion', filteruser=iduser))
    else:
        idg = getidg
        idserverselect = idserver
        getugpolicies = db.session.query(UGPolicies).all()
        getserver = db.session.query(Servers).all()
        getgrupo = db.session.query(Groups).all()
        getpolicies = db.session.query(Policy).all()
        
        for res in getserver:
            if str(idserverselect) == str(res.id):
                server_ip = res.ipadmin
                
        file = open(inventoryfile,'w') # Archivo de inventory de ansible
        file.write('[hostexec]\n')
        file.write(str(server_ip)+'\n')
        file.write('\n')
        file.close()
       
        queryvalidate = GSRelation.query.filter(and_(GSRelation.typeug=="group", GSRelation.idug==idg, GSRelation.idserver==idserverselect)).first()
        if queryvalidate:
            db.session.commit()
        else:
            insertUP = GSRelation(idg, idserverselect, "group")
            db.session.add(insertUP)
            db.session.commit()
        getidsgroups = []
        getpolicyids_list = []
        listpolicy = []
        getgsrelation = db.session.query(GSRelation).all()
        for res in getgsrelation:
            if str(res.idserver) == str(idserverselect):
                getidsgroups.append(res.idug)
        for idspolicies in getugpolicies:
            for idgroup in getidsgroups:
                if idspolicies.type_ug == "group" and idspolicies.id_ug == idgroup:
                    getpolicyids_list.append(idspolicies.id_policy)
        getpolicyids = list(set(getpolicyids_list))
        for idspoli in getpolicies:
            for ids in getpolicyids:
                if idspoli.id == ids:
                    listpolicy.append({idspoli.name: idspoli.policy})
        
        sudoers_delete_policies()
        namepolicies=[]
        for item in listpolicy:
            for key, value in item.items():
                namepolicies.append(key)
                sudoers_policies(key,value)

        group_policies = {}

        # Itera a través de los grupos en getidsgroups
        for idgroup in getidsgroups:
            # Inicializa una lista vacía para las políticas de este grupo
            group_policies[idgroup] = []

            # Itera a través de las políticas y encuentra las que corresponden a este grupo
            for ugpolicy in getugpolicies:
                if str(ugpolicy.id_ug) == str(idgroup) and ugpolicy.type_ug == "group":
                    for getpolicy in getpolicies:
                        if str(getpolicy.id) == str(ugpolicy.id_policy):
                            group_policies[idgroup].append(getpolicy.name)

        sudoers_delete_groups()
        # Ahora, imprime la información de los grupos con sus políticas
        for idgroup, policies in group_policies.items():
            group_name = None
            for res in getgrupo:
                if str(res.id) == str(idgroup):
                    group_name = res.name
            if group_name and policies:
                formatted_policies = ", ".join(policies)
            
                sudoers_groups(group_name,formatted_policies)
        role = ['role-sudo']
        results, status_code = api_playbook_role(role)
        if status_code == 200:
            if results == 4:
                flash(f'Error al intentar conectar al servidor', 'error')
            elif results == 0:
                flash(f'reporte', 'ok')
            elif results == 2:
                flash(f'Tienes que revisar el servidor hay problemas con el playbook', 'error')
        else:
            flash('Error al obtener la respuesta del servidor', 'error')
        
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
    var_ansible(user, groups, mail, "", "")
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

def var_ansible(user, grupos, email, ipserver, namekey):
    logging.info('creating YML file vars')
    apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    ipbastion=apibastion['ip']
    dnsbastion=apibastion['dns']
    file = open('app/ansible/roles/manageCustomUsers/vars/main.yml', 'w')
    file.write('---\n')
    file.write('# vars file for roles/manageCustomUsers\n')
    file.write('\n')
    file.write('usuario: "' + user + '"\n')
    file.write('email: "'+email+', '+reception_mails+'"\n')
    file.write('dirfile: "'+dirfilepem+'/'+user+'"\n')
    file.write('dirgoogle: "'+dirfileqr+'"\n')
    file.write('dirfiles: "'+dirfiles+'"\n')
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
    file.write('\n')
    file.write('grupos:\n')
    for name in grupos:
        file.write('  - '+name+'\n')
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