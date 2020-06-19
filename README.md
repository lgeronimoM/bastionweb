License
-------
BSD

Author Information
------------------
Luis Manuel Geronimo Sandoval 
#SysAdminOne 

Title
------------------
DNSPOWERADMIN

Description
------------------
Administrador web de DNS privados en la intranet
Flask with ansible DNS BIND.

Operation System DNS
------------------
master: Centos7/8
slave: Centos7/8

Dependencies
------------------
install python-pip python-dev ansible python

pip install virtualenv

source yourvitualenv/bin/activate

pip install -r requirements.txt

gunicorn -b 0.0.0.0:4000 -w 4 main:app