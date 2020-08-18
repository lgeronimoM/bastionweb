Licencia
-------
BSD

Autor
------------------
Luis Manuel Geronimo Sandoval 

Canal de youtube #SysAdminOne

Titulo
------------------
DNS Web

Descripción
------------------
Servicio de dns a instalar "ansible".

Aplicacion web con flask en python version 3 para la administracion de accesos de usuarios. 

Sistema Operativo
------------------
Para el maestro: Centos7/8 
 
Para el esclavo: Centos7/8

Recursos
------------------
2 cpu
2GB RAM
10GB HDD
internet

Procesos de instalación
------------------
sudo yum install git

cd /tmp

sudo git clone https://github.com/lgeronimoM/bastionweb.git

cd /tmp/bastionweb

sudo chmod u+x install.sh

sudo ./install.sh

#Habilitar puerto 5000 en el firewall

sudo firewall-cmd --permanent --add-port=5000/tcp

sudo firewall-cmd --reload

sudo systemctl start bastion

acceso web
------------------
usuario: admin
contraseña: bastion
