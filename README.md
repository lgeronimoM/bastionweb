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
servidor web de bastión host.

Un bastión host, también conocido como host de salto (jump host en inglés), es un servidor o sistema informático que se configura de manera segura para actuar como un punto de entrada único a una red privada o segmento de red. Su principal propósito es aumentar la seguridad de una red al limitar el acceso directo a otros sistemas dentro de esa red.

Ademas de que se puede administrar el archivo de sudo en linux con las politicas establecidas.
------------------
SO
------------------
Linux
------------------
Recursos
------------------
2 cpu
2GB RAM
10GB HDD
internet
------------------
Procesos de instalación
------------------

*Habilita el puerto 5000 en el firewall
*Crear y configurar un usuario maestro para el nodo control y todo los nodos clientes

sudo useradd ansadmin
sudo ssh-keygen -t rsa -b 4096 -f ~/.ssh/bastion_ansadmin.pem
sudo ssh-copy-id -i ~/.ssh/bastion_ansadmin.pem ansamdin@192.168.3.x 

*Configurar el archivo sudo
sudo vi /etc/sudoers
#agregar la siguiete linea que otorga permisos de configuracion
ansadmin	ALL=(ALL)	NOPASSWD: ALL

*Instala git
*Descarga el proyecto bastionweb

cd /tmp
sudo git clone https://github.com/lgeronimoM/bastionweb.git
cd /tmp/bastionweb
sudo chmod u+x install.sh
sudo ./install.sh
sudo systemctl start bastion

Generar un llave pem con un usuario ansadmin
------------------
acceso web
------------------
usuario: admin
contraseña: bastion
------------------