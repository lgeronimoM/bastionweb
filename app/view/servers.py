from flask import render_template, redirect, url_for, request, jsonify, send_file, send_from_directory, flash, make_response

# APP MVC
from app import app, cf, login_manager, db
from app.models import Servers, Users, Bastion, Access, Groups, GSRelation, Policy, UGPolicies

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
import os, requests, json, csv
from .bastion import var_ansible_multi_user, update_ip_access, update_data_access, genresources
from .permissions import api_playbook_role, sudoers_groups, sudoers_policies, sudoers_delete_groups, sudoers_delete_policies, inventory_file

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
inventoryfile = cf.HOSTANS

####################### Endpoints #############################

@app.route('/servers', methods=['GET'], defaults={"page_num": 1})
@app.route('/servers/<int:page_num>', methods=['GET'])
@login_required
def servers(page_num):
    servers_all = requests.get(urlservers, headers=headers, verify=False).json()
    apiservers=db.session.query(Servers).paginate(per_page=10, page=page_num, error_out=True)
    filtro=request.args.get('findserver')
    findservers=False
    statusserver= ''
    apibastion=''
    exist = db.session.query(Bastion).filter().first()
    ipbastion = exist.ip
    if exist:
        exist=True
        apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
    else:
        exist=False
    if request.args.get('statusserver'):
        statusserver=request.args.get('statusserver')
    if filtro:
        search = "%{}%".format(filtro)
        apiservers=db.session.query(Servers).filter(or_(Servers.localation.like(search),Servers.hostname.like(search),Servers.namekey.like(search),Servers.ipadmin.like(search))).paginate(per_page=10, page=page_num, error_out=True)
        findservers=True
    logging.info('Access page servers')
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    return render_template('servers.html', ipbastion=ipbastion, user=user, servers_all=servers_all, data=apiservers, mail=mail, findservers=findservers, statusserver=statusserver, findserver=filtro, apibastion=apibastion, exist=exist)

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
    ippro = str(request.form['ipadmin'])
    servicio = str(request.form['servicio'])
    hipervisor = "N/A"
    sistema = "N/A"
    ram = "N/A"
    cpu = "N/A"
    disco = "N/A"
    bastion = bool(request.form.get('bastion'))
    queryserver =  db.session.query(Servers).filter(or_(Servers.hostname==host, Servers.ipadmin==ipadmin, Servers.namekey==name)).first()
    if queryserver:
        #statusadd='Ya existe '+host+' o ip '+ipadmin+' verificalo'
        logging.warning('Ya tiene acceso a bastion '+host)
        flash('Ya tiene acceso a bastion '+host, 'error')
        return redirect(url_for('addserver', validate='Ya existe host o ip favor de validar'))
    else:
        flash('Ya tiene acceso a bastion '+host, 'erro')
        insertQuery = Servers(host,name,descripcion,dns,tipo,departamento,localidad,ipadmin,ippro,servicio,hipervisor,sistema,ram,cpu,disco,bastion)
        db.session.add(insertQuery)
        db.session.commit()
        logging.info('Add server'+' '+name)
    return redirect(url_for('servers'))

@app.route('/comaddsaveserver', methods=['POST'])
@login_required
def comaddsaveserver():
    host = str(request.form['hostname'])
    name = str(request.form['name'])
    descripcion = str(request.form['descripcion'])
    dns = str(request.form['dns'])
    tipo = str(request.form['tipo'])
    departamento = str(request.form['departamento'])
    localidad = str(request.form['localidad'])
    ipadmin = str(request.form['ipadmin'])
    ippro = str(request.form['ipadmin'])
    servicio = str(request.form['servicio'])
    hipervisor = "N/A"
    sistema = "N/A"
    ram = "N/A"
    cpu = "N/A"
    disco = "N/A"
    bastion = bool(request.form.get('bastion'))
    queryserver =  db.session.query(Servers).filter(or_(Servers.hostname==host, Servers.ipadmin==ipadmin, Servers.namekey==name)).first()
    if queryserver:
        #statusadd='Ya existe '+host+' o ip '+ipadmin+' verificalo'
        logging.warning('Ya tiene acceso a bastion '+host)
        flash('Ya tiene acceso a bastion '+host, 'erro')
        return redirect(url_for('addserver', validate='Ya existe host o ip favor de validar'))
    else:
        flash('Se agrega nuevo Server '+host, 'ok')
        insertQuery = Servers(host,name,descripcion,dns,tipo,departamento,localidad,ipadmin,ippro,servicio,hipervisor,sistema,ram,cpu,disco,bastion)
        db.session.add(insertQuery)
        logging.info('Add server'+' '+name)
        db.session.commit()
    return redirect(url_for('addserver'))

@app.route('/addpermissionserver', methods=['GET','POST'], defaults={"page_num": 1})
@app.route('/addpermissionserver/<int:page_num>', methods=['GET','POST'])
@login_required
def addpermissionserver(page_num):
    serverselect = bool(request.args.get('serverselect'))
    getbastion = db.session.query(Bastion).first()
    ipbastion = getbastion.ip
    filtro = request.args.get('server_find')
    getidserverselect = get_server_select()
    getservers = db.session.query(Servers).all()
    getGSrelation = db.session.query(GSRelation).all()
    getidgroupselect = fetch_server_groups(getGSrelation, getidserverselect)
    getgroups = db.session.query(Groups).all()
    getpagination = db.session.query(Groups).paginate(per_page=5, page=page_num, error_out=True)
    removefilter = False
    if filtro:
        search = "%{}%".format(filtro)
        getpagination = db.session.query(Groups).filter(Groups.name.like(search)).paginate(per_page=5, page=page_num, error_out=True)
        removefilter = True
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    validated = request.args.get('validate', '')
    return render_template('addpermissionserver.html', ipbastion=ipbastion, getidgroupselect=getidgroupselect, removefilter=removefilter, getidserverselect=getidserverselect, getpagination=getpagination, user=user, mail=mail, validated=validated, getgroups=getgroups, getservers=getservers)

def fetch_server_groups(getGSrelation, getidserverselect):
    gsrelation = []
    contugsrelation = db.session.query(GSRelation).count()
    for res in getGSrelation:
        if getidserverselect == res.idserver and res.typeug == 'group':
            gsrelation.append(res.idug)
    remaining_length = contugsrelation - len(gsrelation)
    for _ in range(remaining_length):
        gsrelation.append(0)
    return set(gsrelation)

def get_server_select():
    getiduserselect = request.args.get('serverselect')
    if getiduserselect is not None and getiduserselect.lower() != 'false':
        try:
            return int(getiduserselect)
        except ValueError:
            # Manejar el caso en el que getiduserselect no es un número
            return None
    else:
        return None

@app.route('/addrole', methods=['POST'])
@login_required
def addrole():
    idgroups = request.form.getlist('idgroups')
    idserverselect = request.form.get('idserverselect')
    getpolicies = db.session.query(Policy).all()
    getugpolicies = db.session.query(UGPolicies).all()
    getserver = db.session.query(Servers).all()
    getgrupo = db.session.query(Groups).all()
    if idgroups:
        for res in getserver:
            if str(idserverselect) == str(res.id):
                server_ip = res.ipadmin
        
        inventory_file(server_ip)
        for idg in idgroups:
            queryvalidate = GSRelation.query.filter(and_(GSRelation.typeug=="group", GSRelation.idug==idg, GSRelation.idserver==idserverselect)).first()
            if queryvalidate:
                flash('ya existe', 'error')
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
                db.session.rollback()
                flash(f'Error al intentar conectar al servidor', 'error')
            elif results == 0:
                flash(f'Se agrega el grupo {group_name} correctamente', 'ok')
            elif results == 2:
                flash(f'Tienes que revisar el servidor hay problemas con el playbook', 'error')
        else:
            flash('Error al obtener la respuesta del servidor', 'error')
        return redirect(url_for('addpermissionserver', serverselect=idserverselect))
    else:
        flash('No seleccionaste ningun grupo, asegurese por lo menos seleccionar una de la lista de abajo', 'error')
        return redirect(url_for('addpermissionserver', serverselect=idserverselect))
    
@app.route('/deleteroleg', methods=['POST'])
@login_required
def deleteroleg():
    getids = request.form['idrole']
    getids = getids.strip('[]')  # Elimina los corchetes
    idgroup, idserver = map(int, getids.split(',')) 
    getpolicies = db.session.query(Policy).all()
    getugpolicies = db.session.query(UGPolicies).all()
    getgrupo = db.session.query(Groups).all()
    if idgroup:
        datarealtion = GSRelation(typeug="group",idug=idgroup,idserver=idserver)
        db.session.query(GSRelation).filter(and_(GSRelation.typeug == "group", GSRelation.idug == idgroup, GSRelation.idserver == idserver)).delete(synchronize_session=False)
        db.session.commit()
        getidsgroups = []
        getpolicyids_list = []
        listpolicy = []
        getgsrelation = db.session.query(GSRelation).all()
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

        # Ahora, imprime la información de los grupos con sus políticas
        sudoers_delete_groups()
        for idgroup, policies in group_policies.items():
            group_name = None
            for res in getgrupo:
                if str(res.id) == str(idgroup):
                    group_name = res.name
            if group_name and policies:
                formatted_policies = ", ".join(policies)
                #print(f'{group_name} {formatted_policies}')
                sudoers_groups(group_name,formatted_policies)  
        role = ['role-sudo']

        results, status_code = api_playbook_role(role)

        if status_code == 200:
            if results == 4:
                db.session.add(datarealtion)
                db.session.commit()
                flash(f'Error al intentar conectar al servidor', 'error')
            elif results == 0:
                flash(f'Se elimina el grupo {group_name} correctamente', 'ok')
            elif results == 2:
                flash(f'Tienes que revisar el servidor hay problemas con el playbook', 'error')
        else:
            flash('Error al obtener la respuesta del servidor', 'error')
        return redirect(url_for('addpermissionserver', serverselect=idserver))
    else:
        flash('No selecciono ningun grupo', 'error')
        return redirect(url_for('addpermissionserver', serverselect=idserver))

@app.route('/deleteserver', methods=['POST'])
@login_required
def deleteserver():
    idf = int(request.form['id'])
    getgsrelation = db.session.query(GSRelation).all()
    verifyuser = requests.get(urlaccess+'/servers/'+str(idf), headers=headers, verify=False).json()
    if verifyuser:
        flash('Hay accessos activos elimina antes de tomar esta accion', 'error')
        return redirect(url_for('servers'))
    else:
        flash('Server eliminado', 'ok')
        for res in getgsrelation:
            if str(res.idserver) == str(idf) and str(res.typeug) == "group":
                db.session.query(GSRelation).filter(GSRelation.idserver == idf).delete(synchronize_session=False)            
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
    ippro = str(request.form['ipadmin'])
    servicio = str(request.form['servicio'])
    estatus = int(request.form['estatus'])
    servers = requests.get(urlservers, headers=headers, verify=False).json()
    server_id = idf
    nueva_ip = ipadmin
    nuevo_dns = dns
    nuevo_hostname = host
    actualizacion_realizada = False
    ip_nueva = False
    for server in servers:

        if server['id'] == server_id:
            if server['ipadmin'] != nueva_ip:
                # Verificar si la nueva IP ya está asignada a otro servidor
                if any(s['ipadmin'] == nueva_ip for s in servers if s['id'] != server_id):
                    flash('Error al intentar verifica la nueva ip ya esta ocupada'+nueva_ip, 'error')
                    return redirect(url_for('servers'))
                else:
                    server['ipadmin'] = nueva_ip
                    actualizacion_realizada = True
                    ip_nueva = True

            if server['dns'] != dns:
                # Verificar si el nuevo DNS ya está asignado a otro servidor
                if any(s['dns'] == nuevo_dns for s in servers if s['id'] != server_id):
                    flash('Error al intentar verifica el nuevo dns ya esta ocupado '+nuevo_dns, 'error')
                    return redirect(url_for('servers'))
                else:
                    server['dns'] = nuevo_dns
                    actualizacion_realizada = True

            if server['hostname'] != nuevo_hostname:
                # Verificar si el nuevo hostname ya está asignado a otro servidor
                if any(s['hostname'] == nuevo_hostname for s in servers if s['id'] != server_id):
                    flash('Error al intentar verifica el nuevo hostname ya esta ocupado '+nuevo_hostname, 'error')
                    return redirect(url_for('servers'))
                else:
                    server['hostname'] = nuevo_hostname
                    actualizacion_realizada = True
            
            if server['namekey'] != name:
                # Verificar si el nuevo hostname ya está asignado a otro servidor
                if any(s['namekey'] == name for s in servers if s['id'] != server_id):
                    flash('Error al intentar verifica el nuevo nombre clave ya esta ocupado '+name, 'error')
                    return redirect(url_for('servers'))
                else:
                    server['namekey'] = name
                    actualizacion_realizada = True
            break

    if actualizacion_realizada:
        apiaccess = requests.get(urlaccess+'/servers/'+str(idf), headers=headers, verify=False).json()
        if apiaccess:
            ids = []  # Array para almacenar los valores de 'id'
            userids = []  # Array para almacenar los valores de 'userid'
            for server in apiaccess:
                idaccess = server.get('id')
                if idaccess is not None:
                    ids.append(idaccess)
            for server in apiaccess:
                userid = server.get('userid')
                if userid is not None:
                    userids.append(userid)
            filekey=name+'_'+ipadmin+'.pem'
            if ip_nueva:
                file = open(inventoryfile, 'w')
                file.write('[hostexec]\n')
                file.write(f'{ipadmin} nombre_clave_nueva={name} nueva_ip_servidor={ipadmin}\n')
                file.write('\n')
                file.write('[all:vars]\n')
                file.write('usuarios=')
                servers = []
                usuarios = []
                for userid in userids:
                    apiusers = requests.get(urlusers+'/'+str(userid), headers=headers, verify=False).json()
                    username = apiusers['username']
                    usergroup = apiusers['group']
                    usuarios.append({"usuario": username, "grupo": usergroup})
                # Formatear la lista de usuarios sin la coma al final
                usuarios_str = ', '.join([str(usuario) for usuario in usuarios])
                file.write(f"[{usuarios_str}]")
                file.close()
                apiservers = requests.get(urlservers+'/'+str(idf), headers=headers, verify=False).json()
                ipserver=apiservers['ipadmin']
                namekey = apiservers['namekey']
                var_ansible_multi_user(ipserver, namekey)
                exec = update_ip_access()
                if exec==0:
                    logging.info('Edit server'+' '+host)
                    db.session.query(Servers).filter(Servers.id == idf).update({'hostname':host, 'namekey':name, 'description':descripcion, 'dns':dns, 'tipe':tipo, 'department':departamento, 'localation':localidad, 'ipadmin':ipadmin, 'ipprod':ippro, 'service':servicio, 'active':bool(estatus)}) 
                    db.session.commit()
                    for idacs in ids:
                        apiaccess = requests.get(urlaccess+'/'+str(idacs), headers=headers, verify=False).json()
                        idaccess = apiaccess['id']
                        db.session.query(Access).filter(Access.id == idaccess).update({'keypair':filekey, 'server':host})
                        db.session.commit()
                else:
                    return redirect(url_for('servers'))
            else:
                apibastion = requests.get(urlbastion, headers=headers, verify=False).json()
                ipbastion=apibastion['ip']
                file = open(inventoryfile, 'w')
                file.write('[hostexec]\n')
                file.write(f'{ipbastion} nombre_clave_nueva={name} nueva_ip_servidor={ipadmin}\n')
                file.write('\n')
                file.write('[all:vars]\n')
                file.write('usuarios=')
                usuarios = []
                for userid in userids:
                    apiusers = requests.get(urlusers+'/'+str(userid), headers=headers, verify=False).json()
                    username = apiusers['username']
                    usergroup = apiusers['group']
                    usuarios.append({"usuario": username, "grupo": usergroup})
                # Formatear la lista de usuarios sin la coma al final
                usuarios_str = ', '.join([str(usuario) for usuario in usuarios])
                file.write(f"[{usuarios_str}]")
                file.write('\n')
                file.close()
                apiservers = requests.get(urlservers+'/'+str(idf), headers=headers, verify=False).json()
                ipserver=apiservers['ipadmin']
                namekey = apiservers['namekey']
                var_ansible_multi_user(ipserver, namekey)
                exec = update_data_access()
                if exec==0:
                    logging.info('Edit server'+' '+host)
                    flash('ok has modificado un dato verifica', 'ok')
                    db.session.query(Servers).filter(Servers.id == idf).update({'hostname':host, 'namekey':name, 'description':descripcion, 'dns':dns, 'tipe':tipo, 'department':departamento, 'localation':localidad, 'ipadmin':ipadmin, 'ipprod':ippro, 'service':servicio, 'active':bool(estatus)}) 
                    db.session.commit()
                    for idacs in ids:
                        apiaccess = requests.get(urlaccess+'/'+str(idacs), headers=headers, verify=False).json()
                        idaccess = apiaccess['id']
                        db.session.query(Access).filter(Access.id == idaccess).update({'keypair':filekey, 'server':host})
                        db.session.commit()
                else:
                    return redirect(url_for('servers'))
        else:
            flash('ok has modificado un dato verifica', 'ok')
            db.session.query(Servers).filter(Servers.id == idf).update({'hostname':host, 'namekey':name, 'description':descripcion, 'dns':dns, 'tipe':tipo, 'department':departamento, 'localation':localidad, 'ipadmin':ipadmin, 'ipprod':ippro, 'service':servicio, 'active':bool(estatus)}) 
            db.session.commit()
    else:
        flash('ok has modificado un dato verifica', 'ok')
        logging.info('Edit server'+' '+host)
        db.session.query(Servers).filter(Servers.id == idf).update({'hostname':host, 'namekey':name, 'description':descripcion, 'dns':dns, 'tipe':tipo, 'department':departamento, 'localation':localidad, 'ipadmin':ipadmin, 'ipprod':ippro, 'service':servicio, 'active':bool(estatus)}) 
        db.session.commit()
    return redirect(url_for('servers'))

def obtener_informacion(resultados):
    ram = resultados['ram_res']['ansible_memtotal_mb']
    ram_total = round(ram / 1024)
    cpu_total = sum(1 for item in resultados['cpu_res']['ansible_processor'] if item.isdigit())
    tamanio_total = 0

    for dispositivo, info in resultados["store_res"]["ansible_devices"].items():
        if "size" in info:
            tamanio = info["size"]
            tamanio_num = float(tamanio.split(" ")[0])
            unidad = tamanio.split(" ")[1]

            if unidad == "MB":
                tamanio_total += tamanio_num / 1024
            elif unidad == "GB":
                tamanio_total += tamanio_num
            elif unidad == "TB":
                tamanio_total += tamanio_num * 1024

    tamanio_total_entero = int(tamanio_total)
    almacenamiento_total_gb = tamanio_total_entero

    sistema_operativo = resultados['os_res']['ansible_distribution']
    hypervisor = resultados['ser_res']['ansible_virtualization_type'] 
    return ram_total, cpu_total, almacenamiento_total_gb, sistema_operativo, hypervisor

@app.route('/updateresources', methods=['POST'])
@login_required
def updateresources():
    idserver = request.form['idserver']
    apiserver = requests.get(urlservers+'/'+str(idserver), headers=headers, verify=False).json()
    ipserver = apiserver['ipadmin']
    namekey = apiserver['namekey']
    file = open(inventoryfile, 'w')
    file.write('[hostexec]\n')
    file.write(f'{ipserver} namekeyserver={namekey}\n')
    file.write('\n')
    file.close()
    var_ansible_multi_user(ipserver, namekey)
    genresources()
    with open(f'/tmp/resultados_{namekey}.json', 'r') as file:
        contenido = file.read()
    resultados = json.loads(contenido)
    ram, cpu, almacenamiento, so, hypervisor = obtener_informacion(resultados)
    db.session.query(Servers).filter(Servers.id == idserver).update({'ram':ram, 'cpu':cpu, 'storage':almacenamiento, 'os':so, 'hypervisor': hypervisor}) 
    db.session.commit()
    return redirect(url_for('servers'))

@app.route('/getdataservers')
@login_required
def getdataservers():
    apiservers = requests.get(urlservers, headers=headers, verify=False).json()

    # Crear el contenido del archivo CSV en forma de cadena
    csv_data = ""
    for emp in apiservers:
        if not csv_data:
            # Escribir los encabezados del archivo CSV
            csv_data += ','.join(emp.keys()) + '\n'
        # Escribir los datos en el archivo CSV
        csv_data += ','.join(map(str, emp.values())) + '\n'

    # Crear una respuesta con el contenido del archivo CSV
    response = make_response(csv_data)
    
    # Establecer el encabezado Content-Disposition para indicar el nombre del archivo adjunto
    response.headers["Content-Disposition"] = "attachment; filename=data_file.csv"

    # Establecer el tipo MIME del archivo
    response.mimetype = "text/csv"

    return response
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