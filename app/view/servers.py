from flask import render_template, redirect, url_for, request, jsonify, send_file, send_from_directory, flash

# APP MVC
from app import app, cf, login_manager, db
from app.models import Servers, Users, Bastion, Access

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
    return render_template('servers.html', user=user, servers_all=servers_all, data=apiservers, mail=mail, findservers=findservers, statusserver=statusserver, findserver=filtro, apibastion=apibastion, exist=exist)

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
    hipervisor = str(request.form['hipervisor'])
    sistema = str(request.form['sistema'])
    ram = str(request.form['ram'])
    cpu = str(request.form['cpu'])
    disco = str(request.form['disco'])
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

@app.route('/deleteserver', methods=['POST'])
@login_required
def deleteserver():
    idf = int(request.form['id'])
    verifyuser = requests.get(urlaccess+'/servers/'+str(idf), headers=headers, verify=False).json()
    if verifyuser:
        flash('Hay accessos activos elimina antes de tomar esta accion', 'error')
        return redirect(url_for('servers'))
    else:
        flash('Server eliminado', 'ok')
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
    data_file = open('data_file.csv', 'w')
    # create the csv writer object
    csv_writer = csv.writer(data_file)
    # Counter variable used for writing
    # headers to the CSV file
    count = 0
    for emp in apiservers:
        if count == 0:
            # Writing headers of CSV file
            header = emp.keys()
            csv_writer.writerow(header)
            count += 1
        # Writing data of CSV file
        csv_writer.writerow(emp.values())
    data_file.close()
    return send_file("../data_file.csv", mimetype='application/x-csv', attachment_filename='data_file.csv', as_attachment=True)

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

@app.route('/test', methods=['POST'])
def test():
    resul = ''' 
    {"store_res": {
                "ansible_devices": {
                    "dm-0": {
                        "holders": [],
                        "host": "",
                        "links": {
                            "ids": [
                                "dm-name-centos-root",
                                "dm-uuid-LVM-9Pqf7clXPPPwLyor1nfaRlysvRD7qT6EfPGXcO6gZIbO4Z5uNG4zjWa6P7UFdvPw"
                            ],
                            "labels": [],
                            "masters": [],
                            "uuids": [
                                "c71c5aaf-52b5-40bd-b31a-69620546f741"
                            ]
                        },
                        "model": null,
                        "partitions": {},
                        "removable": "0",
                        "rotational": "0",
                        "sas_address": null,
                        "sas_device_handle": null,
                        "scheduler_mode": "",
                        "sectors": "28090368",
                        "sectorsize": "512",
                        "size": "13.39 GB",
                        "support_discard": "0",
                        "vendor": null,
                        "virtual": 1
                    },
                    "dm-1": {
                        "holders": [],
                        "host": "",
                        "links": {
                            "ids": [
                                "dm-name-centos-swap",
                                "dm-uuid-LVM-9Pqf7clXPPPwLyor1nfaRlysvRD7qT6EDI9sbdY5cIzYfYGvDq4FjPOYviBCAffl"
                            ],
                            "labels": [],
                            "masters": [],
                            "uuids": [
                                "f1bf554e-0fd3-46a2-a71a-83eceecbc645"
                            ]
                        },
                        "model": null,
                        "partitions": {},
                        "removable": "0",
                        "rotational": "0",
                        "sas_address": null,
                        "sas_device_handle": null,
                        "scheduler_mode": "",
                        "sectors": "3358720",
                        "sectorsize": "512",
                        "size": "1.60 GB",
                        "support_discard": "0",
                        "vendor": null,
                        "virtual": 1
                    },
                    "sda": {
                        "holders": [],
                        "host": "Serial Attached SCSI controller: VMware PVSCSI SCSI Controller (rev 02)",
                        "links": {
                            "ids": [],
                            "labels": [],
                            "masters": [],
                            "uuids": []
                        },
                        "model": "Virtual disk",
                        "partitions": {
                            "sda1": {
                                "holders": [],
                                "links": {
                                    "ids": [],
                                    "labels": [],
                                    "masters": [],
                                    "uuids": [
                                        "3cb5469e-27ee-4f36-8615-acab250c9689"
                                    ]
                                },
                                "sectors": "2097152",
                                "sectorsize": 512,
                                "size": "1.00 GB",
                                "start": "2048",
                                "uuid": "3cb5469e-27ee-4f36-8615-acab250c9689"
                            },
                            "sda2": {
                                "holders": [
                                    "centos-root",
                                    "centos-swap"
                                ],
                                "links": {
                                    "ids": [
                                        "lvm-pv-uuid-aIFCGl-WWPZ-moLh-Bh0B-bu3m-Joo3-3yu6aR"
                                    ],
                                    "labels": [],
                                    "masters": [
                                        "dm-0",
                                        "dm-1"
                                    ],
                                    "uuids": []
                                },
                                "sectors": "31455232",
                                "sectorsize": 512,
                                "size": "15.00 GB",
                                "start": "2099200",
                                "uuid": null
                            }
                        },
                        "removable": "0",
                        "rotational": "0",
                        "sas_address": null,
                        "sas_device_handle": null,
                        "scheduler_mode": "deadline",
                        "sectors": "33554432",
                        "sectorsize": "512",
                        "size": "16.00 GB",
                        "support_discard": "0",
                        "vendor": "VMware",
                        "virtual": 1
                    },
                    "sr0": {
                        "holders": [],
                        "host": "SATA controller: VMware SATA AHCI controller",
                        "links": {
                            "ids": [
                                "ata-VMware_Virtual_SATA_CDRW_Drive_00000000000000000001"
                            ],
                            "labels": [],
                            "masters": [],
                            "uuids": []
                        },
                        "model": "VMware SATA CD00",
                        "partitions": {},
                        "removable": "1",
                        "rotational": "1",
                        "sas_address": null,
                        "sas_device_handle": null,
                        "scheduler_mode": "deadline",
                        "sectors": "2097151",
                        "sectorsize": "512",
                        "size": "1024.00 MB",
                        "support_discard": "0",
                        "vendor": "NECVMWar",
                        "virtual": 1
                    }
                },
                "changed": false,
                "failed": false
    } } '''
   # Convertir la cadena de texto en un objeto JSON
    resultado_json = json.loads(resul)

    # Obtener todos los dispositivos y sus tamaños
    dispositivos = resultado_json["store_res"]["ansible_devices"]
    tamanio_total = 0

    # Recorrer todos los dispositivos y sumar sus tamaños
    for dispositivo in dispositivos.values():
        if "size" in dispositivo:
            tamanio = dispositivo["size"]
            if tamanio.endswith("GB"):
                tamanio = tamanio.replace(" GB", "")
                tamanio_total += float(tamanio)

    print("El tamaño total de los discos virtuales es: {:.2f} GB".format(tamanio_total))

    return redirect(url_for('servers'))