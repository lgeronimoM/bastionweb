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
Una aplicacion web que ayuda a la administracion y coniguracion de un bastión host.  Un bastión host es como host de salto (jump host en inglés), es un servidor o sistema informático que se configura de manera segura para actuar como un punto de entrada único a una red privada o segmento de red. Su principal propósito es aumentar la seguridad de una red al limitar el acceso directo a otros sistemas dentro de esa red.

Sistema Operativo
------------------
Linux 

Recursos
------------------
2 CPU's
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

-# Tenemos que generar una llave private key para acceder a los servidores con un usario de permisos sudo
-# en este ejemplo yo tengo al usuario ansadmin y tengo esta llave bastion_hosts_ansadmin.pem
-# Generar llave

acceso web
------------------
usuario: admin
contraseña: bastion
