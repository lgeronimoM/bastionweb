from flask import render_template, redirect, url_for, request, jsonify, session, flash
import os, requests, json, sys

# APP MVC
from app import app, cf, login_manager, db
from app.models import Servers, Users, Groups, Policy, UGRelation, UGPolicies, Access, Bastion, GSRelation

#Logs
import logging
from datetime import datetime #Fecha logs

#System
import os, requests, json
from .bastion import deleteuserbastion, bastionclient, copyaccessbastion, inventory_ansible, var_ansible
from .home import validatebastion
from .permissions import api_playbook_role, sudoers_delete_policies, sudoers_delete_groups, sudoers_groups, sudoers_policies, var_ansible_file

#login
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy.orm import sessionmaker
from sqlalchemy import desc
from sqlalchemy import and_, or_
from sqlalchemy.exc import SQLAlchemyError


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
urlapigroups = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/core/v1.0/groups'
urlapiug = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/core/v1.0/ugrelation'
urlgen = "http://"+cf.SERVER+":"+str(cf.PRTO)+'/'
inventoryfile = cf.HOSTANS

@app.route('/users', methods=['GET'], defaults={"page_num": 1})
@app.route('/users/<int:page_num>', methods=['GET'])
@login_required
def users(page_num):
    statususer = ''
    removefilter=False
    filtro=request.args.get('finduser')
    usersall = db.session.query(Users).all()
    apiusers=db.session.query(Users).paginate(per_page=10, page=page_num, error_out=True)
    if request.args.get('statususer'):
        statususer=request.args.get('statususer') 
    if filtro:
        search = "%{}%".format(filtro)
        apiusers=db.session.query(Users).filter(or_(Users.username.like(search),Users.area.like(search))).paginate(per_page=10, page=page_num, error_out=True)
        removefilter=True
    logging.info('Access page users')
    apigroup  = requests.get(urlapigroups, headers=headers, verify=False).json()
    apiug  = requests.get(urlapiug, headers=headers, verify=False).json()
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    return render_template('users.html', user=user, data=apiusers, mail=mail, validatebastion=validatebastion(), removefilter=removefilter, usersall=usersall, apigroup=apigroup, apiug=apiug)

@app.route('/adduser', methods=['GET', 'POST'])
@login_required
def adduser():
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    getgroups = db.session.query(Groups).all()
    mail = queryuser.email
    return render_template('adduser.html', user=user, mail=mail, getgroups=getgroups)

@app.route('/addgroup', methods=['GET', 'POST'])
@login_required
def addgroup():
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    datausers = db.session.query(Users).all()
    mail = queryuser.email
    return render_template('addgroup.html', user=user, mail=mail, data=datausers)

@app.route('/comaddgroup', methods=['POST'])
@login_required
def comaddgroup():
    # Obtener los IDs de los usuarios seleccionados
    idsusers = request.form.get('valuesSeleccts')
    getidsusers = False
    if idsusers:
        elements = idsusers.split(',')
        getidsusers = [int(element) for element in elements]

    # Obtener los datos del formulario
    name = request.form['name']
    desc = request.form['description']

    # Verificar si el grupo ya existe
    query = db.session.query(Groups).filter(Groups.name == name).first()
    if query:
        flash('El grupo ' + name + ' ya existe, verifícalo', 'error')
        logging.warning('El grupo ' + name + ' ya existe')
        return redirect(url_for('addgroup'))

    # Si el grupo no existe, crearlo
    new_group = Groups(name, desc)
    db.session.add(new_group)
    db.session.commit()

    # Obtener el ID del grupo recién creado
    idgroup = new_group.id

    # Asociar usuarios al grupo si se han seleccionado
    if getidsusers:
        for user_id in getidsusers:
            insert_ug = UGRelation(user_id, idgroup)
            db.session.add(insert_ug)
        db.session.commit()

    flash('Se agregó el grupo ' + name + ' exitosamente', 'ok')
    return redirect(url_for('addgroup'))

@app.route('/addpolicy', methods=['GET', 'POST'])
@login_required
def addpolicy():
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    usersall = db.session.query(Users).all()
    mail = queryuser.email
    return render_template('addpolicy.html', user=user, mail=mail, data=usersall)

@app.route('/comaddpolicy', methods=['POST'])
@login_required
def comaddpolicy():
    name = str(request.form['name'])
    desc = str(request.form['description'])
    policies = str(request.form['policy'])
    query =  db.session.query(Policy).filter(or_(Policy.name==name)).first()
    if query:
        flash('Ya existe '+name+' verificalo', 'error')
        logging.warning('Ya existe esta policy '+name)
        return redirect(url_for('users'))
    else:
        insertpolicy = Policy(desc,name,policies)
        db.session.add(insertpolicy)
        db.session.commit()
        return redirect(url_for('users'))

@app.route('/copyaccess', methods=['POST'])
@login_required
def copyaccess():
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    mail = queryuser.email
    iduser = request.form['id']
    queryuser = db.session.query(Users).filter(Users.id==iduser).first()
    usercopy = queryuser.username
    return render_template('copyuseraccess.html', user=user, mail=mail, usercopy=usercopy, idusercopy=iduser)

@app.route('/addusercopyaccess', methods=['POST'])
@login_required
def addusercopyaccess():
    idusercopy = str(request.form['idusercopy'])
    user = str(request.form['username'])
    passwd = str(request.form['password'])
    mail = str(request.form['email'])
    dep = str(request.form['area'])
    active = True
    accessweb = request.form.get('webaccess')
    getugrelation = db.session.query(UGRelation).all()
    getgroupsnames = db.session.query(Groups).all()
    getidsgroups = []
    groups = []
    for res in getugrelation:
        if str(res.id_user) == idusercopy:
            getidsgroups.append(res.id_group)
    for res in getgroupsnames:
        for idgroup in getidsgroups:
            if str(res.id) == str(idgroup):
                groups.append(res.name)
    queryuser =  db.session.query(Users).filter(or_(Users.username==user, Users.email==mail)).first()
    if queryuser:
        flash('Ya existe '+user+' o el '+mail+' verificalo', 'error')
        logging.warning('Ya tiene acceso a bastion '+user)
        return redirect(url_for('users'))
    else:
        if accessweb:
            accessweb=True
        else:
            accessweb=False
        queryuser = db.session.query(Users).filter(Users.username==user).first()
        iduser = queryuser.id
        bastionclient(iduser, user, mail)
        copyaccessbastion(idusercopy, user, mail, groups)
        insertQuery = Users(user,passwd,mail,dep,groups,active,accessweb)
        db.session.add(insertQuery)
        db.session.commit()
        logging.info('Add user'+' '+user)
        flash('El usuario '+user+' fue creado de manera correcta con los accesos', 'ok')
        return redirect(url_for('users'))

@app.route('/comadduser', methods=['POST'])
@login_required
def comadduser():
    idsgroups = request.form.get('valuesSeleccts')
    getidsgroups = False
    if idsgroups:
        elements = idsgroups.split(',')
        getidsgroups = [int(element) for element in elements]

    user = request.form['username']
    passwd = request.form['password']
    mail = request.form['email']
    dep = request.form['area']
    active = bool(int(request.form.get('useractive')))
    webaccess = bool(int(request.form.get('webaccess')))
    
    existing_user = db.session.query(Users).filter(or_(Users.username == user, Users.email == mail)).first()
    if existing_user:
        flash(f'El usuario {user} o el correo {mail} ya existen, verifícalo', 'error')
        logging.warning(f'El usuario {user} ya existe')
        return redirect(url_for('adduser'))

    insertUser = Users(user, passwd, mail, dep, active, webaccess)
    db.session.add(insertUser)
    db.session.commit()
    iduser = insertUser.id

    if active:
        if not bastionclient(iduser, user, mail):
            flash('Error al crear el cliente de bastión', 'error')
            logging.error('Error al crear el cliente de bastión para ' + user)
            db.session.query(Users).filter(Users.id == iduser).delete(synchronize_session=False)
            db.session.commit()
            return redirect(url_for('adduser'))
    
    if getidsgroups:
        for id_group in getidsgroups:
            insertGroup = UGRelation(iduser, id_group)
            db.session.add(insertGroup)

    db.session.commit()

    flash(f'Se creó el usuario {user} de manera correcta', 'ok')
    logging.info(f'Se creó el usuario {user}')
    return redirect(url_for('adduser'))


@app.route('/deleteuser', methods=['POST'])
@login_required
def deleteuser():
    iduser = request.form['id']
    getuser = db.session.query(Users).filter(Users.id == iduser ).first()
    apiug  = requests.get(urlapiug, headers=headers, verify=False).json()
    # Obtener el valor de getidgroup en el primer bucle
    verifyuser = requests.get(urlaccessuser+'/'+str(iduser), headers=headers, verify=False).json()
    server = False
    Client = getuser.status
    for item in verifyuser: 
        if item["tipe"] == "server":
            server=True
    if server:
        flash('usuario tiene accesos activos borrar antes de eliminar', 'error')
    else:
        if Client:
            deleteuserbastion(iduser)

        getgroupsuser = db.session.query(UGRelation).filter(UGRelation.id_user == iduser).all()
        
        if getgroupsuser:
            for res in getgroupsuser:
                db.session.query(UGRelation).filter(and_(UGRelation.id_user == iduser, UGRelation.id_group==res.id_group)).delete(synchronize_session=False)
                db.session.commit()
        db.session.query(Users).filter(Users.id == iduser).delete(synchronize_session=False)
        db.session.commit()  
        flash('Bien el usuario fue eliminado', 'ok')
    return redirect(url_for('users'))

@app.route('/deleteusergroup', methods=['POST'])
@login_required
def deleteusergroup():
    getids = str(request.form['idugrelation'])
    getids = getids.strip('[]')  # Elimina los corchetes
    idgroup, iduser = map(int, getids.split(','))
    getaccess = db.session.query(Access).all()
    getservers = db.session.query(Servers).all()
    getuser = db.session.query(Users).filter(Users.id == iduser).first()
    user = getuser.username
    email = getuser.email
    getidserversaccess = []
    for res in getaccess:
        if res.userid == int(iduser) and res.tipe == "server":
            getidserversaccess.append(res.serverid)
    db.session.query(UGRelation).filter(and_(UGRelation.id_user == iduser, UGRelation.id_group == idgroup )).delete(synchronize_session=False)
    db.session.commit()
    if getidserversaccess: 
        getugrelation = db.session.query(UGRelation).filter(UGRelation.id_user==iduser).all()
        getidsrelationuser = []
        getnamesgroups = []
        for res in getugrelation:
            getidsrelationuser.append(res.id_group)
        getgroups = db.session.query(Groups).all()
        for res in getgroups:
            for idsrelation in getidsrelationuser:
                if res.id == idsrelation:
                    getnamesgroups.append(res.name)

        var_ansible(user, getnamesgroups, email, "", "")

        getipservers = []
        file = open(inventoryfile,'w') # Archivo de inventory de ansible
        file.write('[hostexec]\n')
        for res in getservers:
            for idserver in getidserversaccess:
                if res.id == idserver:
                    getipservers.append(res.ipadmin)
                    file.write(str(res.ipadmin)+'\n')
        file.write('\n')
        file.close()

        role = ['deleterole-sudo']
        response, status_code = api_playbook_role(role)

    flash('La relacion de la politica fue eliminada correctamente', 'ok')
    return redirect(url_for('users'))

@app.route('/edituser', methods=['POST'])
@login_required
def edituser():
    idf = request.form['conf']
    url = cf.APIUSERS+'/'+idf
    apigroup  = requests.get(urlapigroups, headers=headers, verify=False).json()
    apiusers = requests.get(url, headers=headers, verify=False).json()
    apiug  = requests.get(urlapiug, headers=headers, verify=False).json()
    # Obtener el valor de getidgroup en el primer bucle
    listids=[]
    for res in apiug:
        if str(idf) == str(res['id_user']):
            getidgroup = res['id_group']
            listids.append(getidgroup)
    getidgroup = None
    getnamegroup = None
    for res in apigroup:
        if getidgroup == res['id']:
            getnamegroup = res['name']
    user = current_user.username
    queryuser = db.session.query(Users).filter(Users.username==user).first()
    datagroups = db.session.query(Groups).all()
    mail = queryuser.email
    passwd_user = queryuser.password
    #print(listids)
    return render_template('edituser.html', user=user, mail=mail, apiusers=apiusers, passwd_user=passwd_user, datagroups=datagroups, apigroup=apigroup, apiug=apiug, id_user=idf, getnamegroup=getnamegroup, getidgroup=listids)

@app.route('/updateuser', methods=['POST'])
@login_required
def updateuser():
    # Obtener los valores del formulario
    idgroups = request.form.get('valuesSeleccts')
    elements = idgroups.split(',')
    getidsgroups = [int(element) for element in elements]
    
    iduser=int(request.form['idf'])
    username=request.form['username']
    passwd=request.form['passwordnew']
    email=request.form['email']
    area=request.form['area']
    active = bool(int(request.form.get('bastion')))
    webaccess =  bool(int(request.form.get('webaccess')))

    getserverbastion = db.session.query(Bastion).first()
    idbastion = getserverbastion.id
    namekey=getserverbastion.bastion
    ipbastion= getserverbastion.ip
    queryuser = db.session.query(Users).filter(Users.id == iduser).first()
    getgruops = db.session.query(Groups).all()
    getugrelation = db.session.query(UGRelation).all()
    getservers = db.session.query(Servers).all()
    passwd_old = queryuser.password

    groups_to_associate = set(getidsgroups) # inserta la relacion entre usuarios y grupos
    existing_groups = set(res.id_group for res in getugrelation if str(iduser) == str(res.id_user)) 
    groups_to_insert = groups_to_associate - existing_groups  
    for id_group in groups_to_insert:
        insertUGroup = UGRelation(iduser, id_group)
        db.session.add(insertUGroup)
    db.session.commit()

    getidsservers = []  # Inserta la relación entre servidor y grupo
    getGSRelation = db.session.query(Access).filter(and_(Access.tipe == "server", Access.userid == iduser)).all()

    for access in getGSRelation:
        getidsservers.append(access.serverid)
    idservers = list(set(getidsservers))


    for residsg in getidsgroups:
        for idserver in idservers:
            getGSRelation = db.session.query(GSRelation).filter(and_(GSRelation.typeug == "group", GSRelation.idug == residsg, GSRelation.idserver == idserver)).first()
            if getGSRelation:
                pass
            else:
                insertSGroup = GSRelation(typeug="group", idserver=idserver, idug=residsg)
                db.session.add(insertSGroup)
                db.session.commit()

    getnamesGroups= []
    for res in getgruops:
        for idgroup in getidsgroups:
            if res.id == idgroup:
                getnamesGroups.append(res.name)
    var_ansible(username, getnamesGroups, email, ipbastion, namekey) # Variables para grupos e ipbastion
    
    
    listserveruser = []
    getaccess = db.session.query(Access).all()
    for res in getaccess:
        for ids in idservers:
            if str(res.serverid) == str(ids) and str(res.userid) == str(iduser):
                listserveruser.append(res.serverid)
    roleservers(listserveruser, getidsgroups)
    
    apiusers = requests.get(urlusers+'/'+str(iduser), headers=headers, verify=False).json()
    if  area == apiusers['area'] and passwd == passwd_old and email == apiusers['email'] and str(webaccess) == str(apiusers['web']):
        if active:
            # Validar si el acceso ya existe
            validateAccess = Access.query.filter(and_(Access.userid == iduser, Access.tipe == 'client')).first()

            if not validateAccess:
                # Si no existe, crear el acceso
                queryuser = db.session.query(Users).filter(Users.username == username).first()
                iduser = queryuser.id
                filekey = f'{namekey}_{username}.pem'
                fileqrm = f'{namekey}_{username}.txt'

                inventory_ansible()
                role = ['adduser-mfa']
                response, status_code = api_playbook_role(role)

                insertQuery = Access('client', filekey, fileqrm, namekey, username, idbastion, iduser)
                db.session.add(insertQuery)
                db.session.commit()

                logging.warning(f'Generado usuario: {username}')

                if status_code == 200:
                    flash('Se añadió el usuario correctamente', 'ok')
                else:
                    flash(f'Ocurrió un problema, verifica tus servers: {namekey}', 'error')
        else:
            # Si no está activo, eliminar el usuario
            deleteuserbastion(iduser)

        db.session.query(Users).filter(Users.id == iduser).update({'username':username,'password':passwd,'email':email,'area':area,'status':active, 'web': webaccess})
        db.session.commit()
        logging.info('Edit user '+username)
        return redirect(url_for('users'))
    
    else:
        if email != apiusers['email']:
            getusers = db.session.query(Users).all()
            for res in getusers:
                if res.email == email:
                    flash('El Email ya existe valida por favor: '+str(email), 'error')
                    return redirect(url_for('users'))
        db.session.query(Users).filter(Users.id == iduser).update({'username':username,'password':passwd,'email':email,'area':area,'status':active, 'web': webaccess})
        db.session.commit()
        return redirect(url_for('users'))
    
def roleservers(servers, listgroup):
        getugpolicies = db.session.query(UGPolicies).all()
        getpolicies = db.session.query(Policy).all()
        getgrupo = db.session.query(Groups).all()
        role = ['role-sudo']
        listpolicy = []
        getpolicyids_list = []
        for server_relation_id in servers:
            getserver = db.session.query(Servers).filter(Servers.id == server_relation_id).first()
            server_ip = getserver.ipadmin
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
            
            file = open(inventoryfile,'w') # Archivo de inventory de ansible
            file.write('[hostexec]\n')
            file.write(str(server_ip)+'\n')
            file.write('\n')
            file.close()
            #var_ansible_file(server_ip)
            response, status_code = api_playbook_role(role)
        
            # Verifica el código de estado
            if status_code == 200:
                flash('Se agrego correctamente los grupos en el server asociado al usuario '+str(server_ip) , 'ok')
            else:
                flash('ocurrio un problema verifica tus servers: '+str(server_ip), 'error')
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
            flash(post_user+' no tienen permisos suficientes', 'error')
            logging.warning('No es un usuario autorizado '+post_user)
            return redirect(url_for('home'))
    else:
        flash('Usuario o contraseña incorrectos', 'error')
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
        data ={'username': res.username, 'email': res.email, 'area': res.area, 'web': res.web, 'status':res.status, 'id':res.id }
        art.append(data)
    db.session.commit()
    return jsonify(art), 200

@app.route('/core/v1.0/users/<id>')
def apiuserfilt(id):
    query = db.session.query(Users).filter(Users.id.in_([id])).all()
    for res in query:
        data = {'username': res.username, 'email': res.email, 'area': res.area, 'status':res.status, 'web': res.web, 'id':res.id }
    db.session.commit()
    return jsonify(data), 200

@app.route('/core/v1.0/groups')
def apigroup():
    query = db.session.query(Groups).all()
    art=[]
    for res in query:
        data ={'name': res.name, 'desc': res.desc, 'id':res.id }
        art.append(data)
    db.session.commit()
    return jsonify(art), 200

@app.route('/core/v1.0/ugrelation')
def apiugrelation():
    query = db.session.query(UGRelation).all()
    art=[]
    for res in query:
        data ={'id_user': res.id_user, 'id_group': res.id_group, 'id':res.id }
        art.append(data)
    db.session.commit()
    return jsonify(art), 200

@app.route('/core/v1.0/groups/<id>')
def apigroupfilt(id):
    query = db.session.query(Groups).filter(Groups.id.in_([id])).all()
    for res in query:
        data = {'name': res.name, 'desc': res.desc, 'id':res.id  }
    db.session.commit()
    return jsonify(data), 200