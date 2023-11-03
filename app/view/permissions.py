from flask import render_template, redirect, url_for, request, jsonify, session, flash
import os, requests, json, sys, re, io

# APP MVC
from app import app, cf, login_manager, db
from app.models import Servers, Users, UGPolicies, Policy, Groups, GSRelation, UGRelation, Access

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

#System
import os, requests, json

from .home import validatebastion
#login
from flask_login import login_required, current_user
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
urlaccessuser = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/core/v1.0/access/user'
urlgen = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/'
inventoryfile = cf.HOSTANS
userans = cf.USERANS
fileprivatekey = cf.PRIVATEKEY
playbookyml = cf.MAINAPP
varsfile = cf.VARSFILE
userans = cf.USERANS
port_smtp=cf.PORT_SMTP
host_smtp=cf.HOST_SMTP
user_smtp=cf.USER_SMTP
pass_smtp=cf.PASS_SMTP
dirfiles=cf.DIRFILES
dirfilepem=cf.DIRFILEPEM
dirfileqr=cf.DIRFILEQR
reception_mails=cf.RECIVE_MAILS
serverlocal=cf.SERVER

@app.route('/permissions', methods=['GET', 'POST'], defaults={"page_num": 1})
@app.route('/permissions/<int:page_num>', methods=['GET', 'POST'])
@login_required
def permissions(page_num):
    reports = bool(request.args.get('selectusers'))
    policygroups = bool(request.args.get('selectgroups'))
    policies = bool(request.args.get('selectpolicies'))
    getiduserselect = request.args.get('userselect')
    getidgroupselect = get_group_select()
    getugpolicy = db.session.query(UGPolicies).all()
    getservers = db.session.query(Servers).all()
    getugrelation = db.session.query(UGRelation).filter(UGRelation.id_user==getiduserselect).all()
    getpolis = db.session.query(Policy).all()
    getidspoliciesuser = []
    getgroupsuser = []
    for res in getugrelation:
        getgroupsuser.append(res.id_group)
    for idgroup in getgroupsuser:
        for poli in getugpolicy:
            if idgroup == poli.id_ug:
                getidspoliciesuser.append(poli.id_policy)
    getidspoliciesuser=list(set(getidspoliciesuser))
    getaccess = db.session.query(Access).filter(Access.userid==getiduserselect).all()
    gpolicies_set = fetch_group_policies(getugpolicy, getidgroupselect)
    policies = True
    if reports or policygroups:
        policies = False
    removefilter = False
    filtro = request.args.get('policy_find')
    getusers = db.session.query(Users).all()
    getgroups = db.session.query(Groups).all()

    getpolicies = db.session.query(Policy).paginate(per_page=10, page=page_num, error_out=True)  # Asigna un valor predeterminado
    if filtro:
        search = "%{}%".format(filtro)
        getpolicies = db.session.query(Policy).filter(Policy.name.like(search)).paginate(per_page=10, page=page_num, error_out=True)
        removefilter = True
    
    logging.info('Access page users')
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username == user).first()
    mail = queryuser.email
    return render_template('permissions.html', getpolis=getpolis, getidspoliciesuser=getidspoliciesuser, validatebastion=validatebastion(),getservers=getservers, getugrelation=getugrelation, getaccess=getaccess, user=user, reports=reports, getusers=getusers, mail=mail, removefilter=removefilter, policygroups=policygroups, policies=policies, getpolicies=getpolicies, getugpolicy=getugpolicy, getgroups=getgroups, gpolicies=gpolicies_set, getidgroupselect=getidgroupselect ,page_num=page_num, getiduserselect=getiduserselect)

def get_group_select():
    getidgroupselect = request.args.get('groupselect')
    if getidgroupselect is not None and getidgroupselect.lower() != 'false':
        try:
            return int(getidgroupselect)
        except ValueError:
            # Manejar el caso en el que getiduserselect no es un número
            return None
    else:
        return None

def fetch_group_policies(getugpolicy, getidgroupselect):
    ugpolicies = []
    contugpolicy = db.session.query(UGPolicies).count()
    for res in getugpolicy:
        if getidgroupselect == res.id_ug and res.type_ug == 'group':
            ugpolicies.append(res.id_policy)
    remaining_length = contugpolicy - len(ugpolicies)
    for _ in range(remaining_length):
        ugpolicies.append(0)
    return set(ugpolicies) 

@app.route('/addpolicyuser', methods=['POST'])
@login_required
def addpolicyuser():
    idpolicies = request.form.getlist('idpolicy')
    iduser = request.form.get('iduserselect')
    selectusers=True
    if idpolicies:
        for policy_id in idpolicies:
            queryvalidate = UGPolicies.query.filter(and_(UGPolicies.type_ug=="user", UGPolicies.id_ug==iduser, UGPolicies.id_policy==policy_id)).first()
            if queryvalidate:
                db.session.commit()
            else:
                insertUP = UGPolicies("user",iduser,policy_id)
                db.session.add(insertUP)
                db.session.commit()
                flash('se agrega correctamente las politicas puedes verificar seleccionando el usuario nuevamente', 'ok')
        return redirect(url_for('permissions', selectusers=selectusers))
    else:
        flash('No seleccionaste ninguna política, asegurese por lo menos seleccionar una de la lista de abajo', 'error')
        return redirect(url_for('permissions', selectusers=selectusers))

@app.route('/addpolicygroup', methods=['POST'])
@login_required
def addpolicygroup():
    idpolicies = request.form.getlist('idpolicy')
    idgroup = request.form.get('idgroupselect')
    idgroupselect = idgroup
    
    getpolicies = db.session.query(Policy).all()
    getservers = db.session.query(Servers).all()
    getgrupo = db.session.query(Groups).all()
    if idpolicies:
        for policy_id in idpolicies:
            queryvalidate = UGPolicies.query.filter(and_(UGPolicies.type_ug=="group", UGPolicies.id_ug==idgroup, UGPolicies.id_policy==policy_id)).first()
            if queryvalidate:
                flash('ya existe el grupo', 'error')
                db.session.commit()
            else:
                insertUP = UGPolicies("group",idgroup,policy_id)
                db.session.add(insertUP)
                db.session.commit()
    else:
        flash('No seleccionaste ninguna política, asegurese por lo menos seleccionar una de la lista de abajo', 'error')
        return redirect(url_for('permissions', selectgroups=True, groupselect=idgroupselect))

    servers = []
    serversids = []
    getpolicyids_list = []
    listpolicy = []
    getGSrelation = db.session.query(GSRelation).all()
    for resGS in getGSrelation:
        if resGS.idug == int(idgroup) and resGS.typeug == "group":
            for resid in getservers:
                if resGS.idserver == resid.id:
                    servers.append(resid.ipadmin)
                    serversids.append(resid.id)
    if servers:
        getugpolicies = db.session.query(UGPolicies).all()
        role = ['policy-sudo']
        listgroup = []
        
        for server_relation_id, server_ip in zip(serversids, servers):
            for idsgroups in getGSrelation:
                if str(idsgroups.idserver) == str(server_relation_id) and idsgroups.typeug == "group":
                    listgroup.append(idsgroups.idug)
            
            for idspolicies in getugpolicies:
                for idgroup in listgroup:
                    if idspolicies.type_ug == "group" and idspolicies.id_ug == idgroup:
                        getpolicyids_list.append(idspolicies.id_policy)
            getpolicyids = list(set(getpolicyids_list))
            for idspoli in getpolicies:
                for ids in getpolicyids:
                    if idspoli.id == ids:
                        listpolicy.append({idspoli.name: idspoli.policy})
          
            namepolicies=[]
            sudoers_delete_policies()
            for item in listpolicy:
                for key, value in item.items():
                    namepolicies.append(key)
                    sudoers_policies(key, value)

            group_policies = {}
        
            # Itera a través de los grupos en getidsgroups
            for idgroup in listgroup:
                # Inicializa una lista vacía para las políticas de este grupo
                group_policies[idgroup] = []

                # Itera a través de las políticas y encuentra las que corresponden a este grupo
                for ugpolicy in getugpolicies:
                    if str(ugpolicy.id_ug) == str(idgroup) and ugpolicy.type_ug == "group":
                        for getpolicy in getpolicies:
                            if str(getpolicy.id) == str(ugpolicy.id_policy):
                                group_policies[idgroup].append(getpolicy.name)

            # Ahora, imprime la información de los grupos con sus políticas
            sudoers_delete_groups()
            for idgroup, policies in group_policies.items():
                group_name = None
                for res in getgrupo:
                    if str(res.id) == str(idgroup):
                        group_name = res.name
                if group_name and policies:
                    formatted_policies = ", ".join(policies)
                    sudoers_groups(group_name,formatted_policies)

            inventory_file(server_ip)
            var_ansible_file("", [], "", server_ip, "")
            
            results, status_code = api_playbook_role(role)

            if status_code == 200:
                if results == 4:
                    db.session.delete(insertUP)
                    db.session.commit()
                    flash(f'Error al intentar conectar al servidor {server_ip}', 'error')
                elif results == 0:
                    flash(f'Se agrega la política correctamente en el server {server_ip}', 'ok')
                elif results == 2:
                    flash(f'hubo un problema con el playbook en el {server_ip}', 'error')
            else:
                flash('Error al obtener la respuesta del servidor', 'error')
        return redirect(url_for('permissions', selectgroups=True, groupselect=idgroupselect))
    else:
        insertUP = UGPolicies("group",idgroup,policy_id)
        db.session.add(insertUP)
        db.session.commit()
        flash('Se agregan todas las politicas de manera correcta', 'ok')

    return redirect(url_for('permissions', selectgroups=True, groupselect=idgroupselect))
    
@app.route('/deletepermission', methods=['POST'])
@login_required
def deletepermission():
    idpolicy = str(request.form['idpolicy'])
    db.session.query(UGPolicies).filter(UGPolicies.id == idpolicy).delete(synchronize_session=False)
    db.session.commit()  
    flash('La relacion de la politica fue eliminada correctamente', 'ok')
    return redirect(url_for('permissions'))


@app.route('/getreportuser', methods=['POST'])
@login_required
def getreportuser():
    datauser = request.form['getidserver']
    datauser = datauser.strip('[]')  # Elimina los corchetes
    ipserver, iduser = datauser.split(',')
    getusers = db.session.query(Users).filter(Users.id == iduser).first()
    getusername = getusers.username
    email = getusers.email
    inventory_file(ipserver)
    var_ansible_file(getusername, [], email, ipserver, "")
    
    role = ['report']
    response, status_code = api_playbook_role(role)
    
    input_file = dirfiles+'/audit/audit_'+getusername+'_'+ipserver+'.txt'
    output_file = dirfiles+'/audit/audit_filt_'+getusername+'_'+ipserver+'.txt'
    outfilter = dirfiles+'/audit/audit_report_'+getusername+'_'+ipserver+'.txt'
    process_audit_logs_from_file(input_file, output_file)
    generate_report(output_file, outfilter)
    
    role = ['send-report']

    results, status_code = api_playbook_role(role)

    if status_code == 200:
        if results == 4:
            flash(f'Error al intentar conectar al servidor {ipserver}', 'error')
        elif results == 0:
            flash('Se genera el reporte del usuario '+getusername+'del servidor '+ipserver, 'ok')
        elif results == 2:
            flash(f'hubo un problema con el playbook en el {ipserver}', 'error')
    else:
        flash('Error al obtener la respuesta del servidor', 'error')
    
    return redirect(url_for('permissions', selectusers=True, userselect=iduser))

def generate_report(records_file, out_file):
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

def process_audit_logs_from_file(record, out_file):
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

@app.route('/deletepolicygroup', methods=['POST'])
@login_required
def deletepolicygroup():
    servers = []
    getids = request.form['idpolicygroup']
    getids = getids.strip('[]')  # Elimina los corchetes
    idpolicy, idgroup = map(int, getids.split(',')) 
    idgroupselect = idgroup 
    getGSrelation = db.session.query(GSRelation).all()
    getservers = db.session.query(Servers).all()
    getpolicies = db.session.query(Policy).all()
    getgrupo = db.session.query(Groups).all()
    serversids = []
    getidsgroups = []
    getpolicyids_list = []
    listpolicy = []
    for getname in getgrupo:
        if str(getname.id) == str(idgroup):
            namegroup = getname.name
    for res in getGSrelation:
        if res.idug == idgroup and res.typeug == "group":
            for resid in getservers:
                if res.idserver == resid.id:
                    servers.append(resid.ipadmin)
                    serversids.append(resid.id)
    if servers:
        db.session.query(UGPolicies).filter(and_(UGPolicies.type_ug == "group", UGPolicies.id_ug == idgroup, UGPolicies.id_policy == idpolicy)).delete(synchronize_session=False)
        db.session.commit()
        getugpolicies = db.session.query(UGPolicies).all()
        role = ['policy-sudo']
        listgroup = []
        getidspolicies = []
        for server_relation_id, server_ip in zip(serversids, servers):
            for idsgroups in getGSrelation:
                if str(idsgroups.idserver) == str(server_relation_id) and idsgroups.typeug == "group":
                    listgroup.append(idsgroups.idug)
            for idspolicies in getugpolicies:
                for idgroup in listgroup:
                    if idspolicies.type_ug == "group" and idspolicies.id_ug == idgroup:
                        getpolicyids_list.append(idspolicies.id_policy)
            getpolicyids = list(set(getpolicyids_list))
            for idspoli in getpolicies:
                for ids in getpolicyids:
                    if idspoli.id == ids:
                        listpolicy.append({idspoli.name: idspoli.policy})
            namepolicies=[]
            sudoers_delete_policies()
            for item in listpolicy:
                for key, value in item.items():
                    namepolicies.append(key)
                    sudoers_policies(key,value)

            group_policies = {}

            # Itera a través de los grupos en getidsgroups
            for idgroup in listgroup:
                # Inicializa una lista vacía para las políticas de este grupo
                group_policies[idgroup] = []

                # Itera a través de las políticas y encuentra las que corresponden a este grupo
                for ugpolicy in getugpolicies:
                    if str(ugpolicy.id_ug) == str(idgroup) and ugpolicy.type_ug == "group":
                        for getpolicy in getpolicies:
                            if str(getpolicy.id) == str(ugpolicy.id_policy):
                                group_policies[idgroup].append(getpolicy.name)

            # Ahora, imprime la información de los grupos con sus políticas
            sudoers_delete_groups()
            for idgroup, policies in group_policies.items():
                group_name = None
                for res in getgrupo:
                    if str(res.id) == str(idgroup):
                        group_name = res.name
                if group_name and policies:
                    formatted_policies = ", ".join(policies)
                    sudoers_groups(group_name,formatted_policies)
            
            inventory_file(server_ip)
            var_ansible_file("", [], "", server_ip, "")
            
            results, status_code = api_playbook_role(role)

            if status_code == 200:
                if results == 4:
                    flash(f'Error al intentar conectar al servidor {server_ip}', 'error')
                elif results == 0:
                    flash(f'Se removio la política correctamente en el server {server_ip}', 'ok')
                elif results == 2:
                    flash(f'hubo un problema con el playbook en el {server_ip}', 'error')
            else:
                flash('Error al obtener la respuesta del servidor', 'error')
    else:
        db.session.query(UGPolicies).filter(and_(UGPolicies.type_ug == "group", UGPolicies.id_ug == idgroup, UGPolicies.id_policy == idpolicy)).delete(synchronize_session=False)
        db.session.commit()
        flash('Se removio el policy correctamente', 'ok')
    return redirect(url_for('permissions', selectgroups=True, groupselect=idgroupselect))

def sudoers_groups(namegroup,namepolicies):
    palabra_clave1 = '## Roles to Groups'
    palabra_clave2 = f'%{namegroup}'
    # Lee el contenido actual del archivo sudoers
    with open(varsfile, 'r') as archivo:
        lineas = archivo.readlines()
    # Busca la línea que contiene la palabra clave 1
    indice_linea_palabra_clave1 = None
    for i, linea in enumerate(lineas):
        if palabra_clave1 in linea:
            indice_linea_palabra_clave1 = i
            break
    # Busca la línea que contiene la palabra clave 2
    indice_linea_palabra_clave2 = None
    for i, linea in enumerate(lineas):
        if palabra_clave2 in linea:
            indice_linea_palabra_clave2 = i
            break
    # Si se encuentra la palabra clave 1, y se encuentra la palabra clave 2 debajo, reemplaza la línea existente
    if indice_linea_palabra_clave1 is not None and indice_linea_palabra_clave2 is not None:
        nueva_configuracion_linea = f'%{namegroup} ALL = NOPASSWD: {namepolicies} \n'
        lineas[indice_linea_palabra_clave2] = nueva_configuracion_linea
        # Escribe el nuevo contenido en el archivo
        with open(varsfile, 'w') as archivo:
            archivo.writelines(lineas)
    # Si se encuentra la palabra clave 1, pero no la palabra clave 2, agrega la nueva configuración después de la palabra clave 1
    elif indice_linea_palabra_clave1 is not None and indice_linea_palabra_clave2 is None:
        nueva_configuracion_linea = f'%{namegroup} ALL = NOPASSWD: {namepolicies} \n'
        lineas.insert(indice_linea_palabra_clave1 + 1, nueva_configuracion_linea)
        # Escribe el nuevo contenido en el archivo
        with open(varsfile, 'w') as archivo:
            archivo.writelines(lineas)
    # Si no se encuentra la palabra clave 1, simplemente agrega la nueva configuración al final del archivo
    else:
        with open(varsfile, 'a') as archivo:
            archivo.write(f'\n{palabra_clave1}\n%{namegroup} ALL = {namepolicies} NOPASSWD: ALL\n')

def sudoers_policies(key,value):
    palabra_clave = '## Command Aliases'
    with open(varsfile, 'r') as archivo:
        lineas = archivo.readlines()
    # Busca la línea que contiene la palabra clave
    indice_linea_palabra_clave = None
    for i, linea in enumerate(lineas):
        if palabra_clave in linea:
            indice_linea_palabra_clave = i
            break
    # Define la nueva configuración que deseas agregar
    nueva_configuracion_linea = f'Cmnd_Alias {key} = {value}\n'
    # Si se encuentra la palabra clave, verifica si la nueva configuración ya existe
    if indice_linea_palabra_clave is not None:
        configuracion_existente = f'Cmnd_Alias {key}'
        nueva_configuracion_existente = f'Cmnd_Alias {key} = {value}'
        # Si la configuración ya existe, reemplaza la línea
        if any(configuracion_existente in linea for linea in lineas):
            for i, linea in enumerate(lineas):
                if configuracion_existente in linea:
                    lineas[i] = nueva_configuracion_linea
                    break
        # Si la configuración no existe, agrégala después de la palabra clave
        else:
            lineas.insert(indice_linea_palabra_clave + 1, nueva_configuracion_linea)
    else:
        # Si no se encuentra la palabra clave, simplemente agrega la nueva configuración al final del archivo
        lineas.append(f'\n{palabra_clave}\n{nueva_configuracion_linea}')
    # Escribe el nuevo contenido en el archivo
    with open(varsfile, 'w') as archivo:
        archivo.writelines(lineas)

def sudoers_delete_groups():
    # Palabra clave para buscar
    keyword = '## Roles to Groups'

    # Lee el contenido actual del archivo sudoers
    with open(varsfile, 'r') as file:
        lines = file.readlines()

    # Encuentra la línea que contiene la palabra clave
    keyword_line_index = None
    for i, line in enumerate(lines):
        if keyword in line:
            keyword_line_index = i
            break

    if keyword_line_index is not None:
        # Si se encuentra la línea con la palabra clave, elimina las líneas que le siguen
        del lines[keyword_line_index + 1:]

        # Escribe el nuevo contenido en el archivo
        with open(varsfile, 'w') as file:
            file.writelines(lines)

def sudoers_delete_policies():
    # Palabras clave para buscar
    start_keyword = '## Command Aliases'
    end_keyword = '## end Cmnd_Alias'

    # Lee el contenido actual del archivo sudoers
    with open(varsfile, 'r') as file:
        lines = file.readlines()

    # Encuentra la línea que contiene la palabra clave de inicio
    start_keyword_line_index = None
    for i, line in enumerate(lines):
        if start_keyword in line:
            start_keyword_line_index = i
            break

    if start_keyword_line_index is not None:
        # Encuentra la línea que contiene la palabra clave de fin
        end_keyword_line_index = None
        for i in range(start_keyword_line_index, len(lines)): 
            if end_keyword in lines[i]:
                end_keyword_line_index = i
                break

        if end_keyword_line_index is not None:
            # Elimina las líneas que están entre las palabras clave de inicio y fin
            del lines[start_keyword_line_index + 1:end_keyword_line_index]

            # Escribe el nuevo contenido en el archivo
            with open(varsfile, 'w') as file:
                file.writelines(lines)

def api_playbook_role(role):
    tagsexc=role
    keyfile=fileprivatekey
    play=playbookyml
    user=userans
    inventory=inventoryfile
    ssh_extra_args = "-o StrictHostKeyChecking=no"
    loader = DataLoader()
    context.CLIARGS = ImmutableDict(tags=tagsexc, listtags=False, listtasks=False, listhosts=False, syntax=False, connection='ssh',
                        module_path=None, forks=10, remote_user=user, private_key_file=keyfile,
                        ssh_common_args=None, ssh_extra_args=ssh_extra_args, sftp_extra_args=None, scp_extra_args=None, become=True,
                        become_method='sudo', become_user='root', verbosity=True, check=False, start_at_task=None,
                        extra_vars={})
    inventory = InventoryManager(loader=loader, sources=(inventory))
    variable_manager = VariableManager(loader=loader, inventory=inventory, version_info=CLI.version_info(gitinfo=False))
    pbex = PlaybookExecutor(playbooks=[play], inventory=inventory, variable_manager=variable_manager, loader=loader, passwords={})
    results = pbex.run()
    db.session.commit()
    return results, 200

def var_ansible_file(user, grupos, email, ipserver, namekey):
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

def inventory_file(server_ip):
    file = open(inventoryfile,'w') # Archivo de inventory de ansible
    file.write('[hostexec]\n')
    file.write(str(server_ip)+'\n')
    file.write('\n')
    file.close() 