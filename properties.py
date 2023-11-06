__author__ = 'Luis Manuel Geronimo Sandoval'

import logging

class Config(object):
    # properties Admin
    LINK='/admin'
    TEM='bootstrap3'
    NAMEAPP= 'Bastion'
    # properties for Email
    USER_SMTP= 'ejemplo_user@gmail.com'
    HOST_SMTP= 'smtp.gmail.com'
    PORT_SMTP= 587
    PASS_SMTP= 'PASSWD_SMTP'
    RECIVE_MAILS='usernotify1@gmail.com, usernotify2@gmail.com, usernotify3@gmail.com'
    #Level log
    LOG_LEVEL = logging.DEBUG
    SECRETKEY= 'SECRET_KEY_WORD' 
    
class ProductionConfig(Config):
    DEBUG=False
    # properties host
    SERVER='0.0.0.0'
    #ANSIBLE datos
    USERANS='ansadmin'
    PASSWDANS=''
    VARSFILE='/etc/bastion/app/ansible/roles/manageCustomUsers/files/sudoers'
    PRIVATEKEY='/etc/bastion/PEMFiles/bastion_hosts_ansadmin.pem'
    HOSTANS='/etc/bastion/app/ansible/inventory'
    MAINAPP='/etc/bastion/app/ansible/manageCustomUsers.yml'
    DIRFILEPEM= '/etc/bastion/PEMFiles'
    DIRFILEQR= '/etc/bastion/google-auth'
    DIRFILES= '/etc/bastion/files'
    # properties SQlite
    DB_DIR = 'sqlite:////etc/bastion/db/data.db'
    # Log
    LOG_DIR='/var/log/bastion/bastion_%d_%m_%Y.log'
    # Port
    PRTO = 5000
    #local
    _SERLOCAL=str('http://'+SERVER+':'+str(PRTO))
    # Api servers
    APISERVERS=_SERLOCAL+'/core/v1.0/servers'
    # Api user
    APIUSERS=_SERLOCAL+'/core/v1.0/users'
    # Api bastion
    APIBASTION=_SERLOCAL+'/core/v1.0/bastion'
    # Api access
    APIACCESS=_SERLOCAL+'/core/v1.0/access'
    # ruta LOG
    RUTALOG = '/var/log/message'

class DevelopmentConfig(Config):
    DEBUG=True
    # properties host
    SERVER='127.0.0.1'
    #ANSIBLE datos
    USERANS='ansadmin'
    PASSWDANS=''
    VARSFILE='app/ansible/roles/manageCustomUsers/files/sudoers'
    PRIVATEKEY='files/PEMFiles/bastion_hosts_ansadmin.pem'
    HOSTANS='app/ansible/inventory'
    MAINAPP='app/ansible/manageCustomUsers.yml'
    #DIRFILEPEM= '/home/'+USERANS+'/bastionWeb/files/PEMFiles'
    DIRFILEPEM= '/home/ansadmin'
    DIRFILEQR= '/home/ansadmin'
    DIRFILES= '/home/luisgeronimo/Documents/Desarrollos/flask/bastionWEB/files'
    # properties SQlite
    DB_DIR = 'sqlite:///../db/des-data.db'
    # Log
    LOG_DIR='logs/bastion_%d_%m_%Y.log'
    # Port
    PRTO = 8292
    #local
    _SERLOCAL=str('http://'+SERVER+':'+str(PRTO))
    # Api servers
    APISERVERS=_SERLOCAL+'/core/v1.0/servers'
    # Api user
    APIUSERS=_SERLOCAL+'/core/v1.0/users'
    # Api bastion
    APIBASTION=_SERLOCAL+'/core/v1.0/bastion'
    # Api access
    APIACCESS=_SERLOCAL+'/core/v1.0/access'
    # ruta LOG
    RUTALOG = '/home/luisgeronimo/Documents/Desarrollos/flask/bastionWEB/logs/bastion_%d_%m_%Y.log'
    