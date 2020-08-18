__author__ = 'Luis Geronimo'

import logging

class Config(object):
    # properties Admin
    LINK='/admin'
    TEM='bootstrap3'
    NAMEAPP= 'Bastion'
    LOG_LEVEL = logging.DEBUG

class ProductionConfig(Config):
    DEBUG=False
    # properties host
    SERVER='0.0.0.0'
    #ANSIBLE datos
    USERANS='ansadmin'
    PASSWDANS=''
    PRIVATEKEY='/etc/bastion/bastionWEB/app/ansible/bastion_hosts_ansadmin.pem'
    HOSTANS='/etc/bastion/bastionWEB/app/ansible/inventory'
    MAINAPP='/etc/bastion/bastionWEB/app/ansible/manageCustomUsers.yml'
    DIRFILEPEM= '/etc/bastion/bastionWEB/app/ansible/PEMFiles'
    DIRFILEQR= '/etc/bastion/bastionWEB/app/ansible/google-auth'
    USER_SMTP= ''
    HOST_SMTP= 'smtp.office365.com'
    PORT_SMTP= 587
    PASS_SMTP= ''
    RECIVE_MAILS=''
    # properties SQlite
    DB_DIR = 'sqlite:///db/data.db'
    # Log
    LOG_DIR='/var/log/bastion/bastion_%d_%m_%Y.log'
    # Port
    PRTO = 5000
    #local
    _SERLOCAL=str('http://'+SERVER+':'+str(PRTO))
    #Service
    _SER=str('http://10.190.5.42:'+str(PRTO))
    # Api servers
    APISERVERS=_SERLOCAL+'/core/v1.0/servers'
    # Api User
    APIUSER=_SER+'/core/v1.0/apiuser' 
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
    PRIVATEKEY='/mnt/c/Users/LP-0220/Documents/Desarrollos/flask/bastionWEB/app/ansible/bastion_hosts_ansadmin.pem'
    HOSTANS='/mnt/c/Users/LP-0220/Documents/Desarrollos/flask/bastionWEB/app/ansible/inventory'
    MAINAPP='/mnt/c/Users/LP-0220/Documents/Desarrollos/flask/bastionWEB/app/ansible/manageCustomUsers.yml'
    DIRFILEPEM= '/mnt/c/Users/LP-0220/Documents/Desarrollos/flask/bastionWEB/app/ansible/PEMFiles'
    DIRFILEQR= '/mnt/c/Users/LP-0220/Documents/Desarrollos/flask/bastionWEB/app/ansible/google-auth'
    USER_SMTP= ''
    HOST_SMTP= 'smtp.office365.com'
    PORT_SMTP= 587
    PASS_SMTP= ''
    RECIVE_MAILS=''
    # properties SQlite
    DB_DIR = 'sqlite:///db/des-data.db'
    # Log
    LOG_DIR='bastion_%d_%m_%Y.log'
    # Port
    PRTO = 8292
    #local
    _SERLOCAL=str('http://'+SERVER+':'+str(PRTO))
    #service
    _SER='http://10.190.5.42:4000'
    # Api servers
    APISERVERS=_SERLOCAL+'/core/v1.0/servers'
    # Api User
    APIUSER=_SER+'/core/v1.0/apiuser' 
    # Api user
    APIUSERS=_SERLOCAL+'/core/v1.0/users'
    # Api bastion
    APIBASTION=_SERLOCAL+'/core/v1.0/bastion'
    # Api access
    APIACCESS=_SERLOCAL+'/core/v1.0/access'