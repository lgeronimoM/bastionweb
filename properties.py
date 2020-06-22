__author__ = 'Luis Geronimo'

import logging

class Config(object):
    # propiedades Admin
    LINK='/admin'
    TEM='bootstrap3'
    NAMEAPP= 'DNS'
    # propiedades para Email
    #PMAIL = 587  # For starttls
    #SMTP = ''
    #SEMAIL = ''
    #EPASS = ''
    #REMAIL = ''
    LOG_LEVEL = logging.DEBUG

class ProductionConfig(Config):
    DEBUG=False
    # propiedades host
    SERVER='0.0.0.0'
    # propiedades SQlite
    DB_DIR = 'sqlite:///db/data.db'
    # Log
    LOG_DIR='/var/log/dnsweb/dns_web_%d_%m_%Y.log'
    # Puerto
    PRTO = 4000
    #Service
    _SER=str('http://'+SERVER+':'+str(PRTO))
    # Api hosted zones
    APIHOSETD=_SER+'/core/v1.0/hostedzone'
    # Api User
    APIUSER=_SER+'/core/v1.0/apiuser'
    # Api domain
    APIDOMAIN=_SER+'/core/v1.0/domain/'

class DevelopmentConfig(Config):
    DEBUG=True
    # propiedades host
    SERVER='127.0.0.1'
    # Propiedades SQlite
    DB_DIR = 'sqlite:///db/des-data.db'
    # Log
    LOG_DIR='dns_web_%d_%m_%Y.log'
    # Puerto
    PRTO = 8292
    #service
    _SER=str('http://'+SERVER+':'+str(PRTO))
    # Api hosted zones
    APIHOSETD=_SER+'/core/v1.0/hostedzone'
    # Api User
    APIUSER=_SER+'/core/v1.0/apiuser' 
    # Api domain
    APIDOMAIN=_SER+'/core/v1.0/domain/'
