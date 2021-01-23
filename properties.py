__author__ = 'Luis Geronimo'

import logging

class Config(object):
    # properties Admin
    LINK='/admin'
    TEM='bootstrap3'
    NAMEAPP= 'Bastion'
    # properties for Email
    USER_SMTP= 'notificacionesti@encontrack.com'
    HOST_SMTP= 'smtp.office365.com'
    PORT_SMTP= 587
    PASS_SMTP= 'Das52564'
    RECIVE_MAILS='luis.geronimo@encontrack.com'
    #Level log
    LOG_LEVEL = logging.DEBUG
    SECRETKEY= 'des'
    
class ProductionConfig(Config):
    DEBUG=False
    # properties host
    SERVER='0.0.0.0'
    #ANSIBLE datos
    USERANS='ansadmin'
    PASSWDANS=''
    PRIVATEKEY='/etc/bastion/PEMFiles/bastion_hosts_ansadmin.pem'
    HOSTANS='/etc/bastion/app/ansible/inventory'
    MAINAPP='/etc/bastion/app/ansible/manageCustomUsers.yml'
    DIRFILEPEM= '/etc/bastion/PEMFiles'
    DIRFILEQR= '/etc/bastion/google-auth'
    # properties SQlite
    DB_DIR = 'sqlite:///db/data.db'
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

class DevelopmentConfig(Config):
    DEBUG=True
    # properties host
    SERVER='127.0.0.1'
    #ANSIBLE datos
    USERANS='ansadmin'
    PASSWDANS=''
    PRIVATEKEY='/home/lgeronimo/Documents/Desarrollos/flask/bastionWEB/files/PEMFiles/bastion_hosts_ansadmin.pem'
    HOSTANS='/home/lgeronimo/Documents/Desarrollos/flask/bastionWEB/app/ansible/inventory'
    MAINAPP='/home/lgeronimo/Documents/Desarrollos/flask/bastionWEB/app/ansible/manageCustomUsers.yml'
    DIRFILEPEM= '/home/lgeronimo/Documents/Desarrollos/flask/bastionWEB/files/PEMFiles'
    DIRFILEQR= '/home/lgeronimo/Documents/Desarrollos/flask/bastionWEB/files/google-auth'
    # properties SQlite
    DB_DIR = 'sqlite:////home/lgeronimo/Documents/Desarrollos/flask/bastionWEB/db/des-data.db'
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
