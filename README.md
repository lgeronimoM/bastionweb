# DNS Web en Bastión Host

## Licencia
BSD

## Autor
Luis Manuel Geronimo Sandoval

- Canal de YouTube: #SysAdminOne

## Descripción
Este proyecto implementa un servidor web en un bastión host. Un bastión host, también conocido como host de salto (jump host en inglés), es un servidor o sistema informático que se configura de manera segura para actuar como un punto de entrada único a una red privada o segmento de red. Su principal propósito es aumentar la seguridad de una red al limitar el acceso directo a otros sistemas dentro de esa red. Además, se puede administrar el archivo de sudo en Linux con políticas establecidas.

## Sistema Operativo
Linux

## Recursos
- 2 CPU
- 2GB de RAM
- 10GB de Disco Duro
- Conexión a Internet

## Procesos de Instalación
1. **Habilita el puerto 5000 en el firewall.**

2. **Crear y configurar un usuario maestro para el nodo de control y los nodos clientes:**

   ```bash
   sudo useradd ansadmin
   sudo ssh-keygen -t rsa -b 4096 -f ~/.ssh/bastion_ansadmin.pem
   sudo ssh-copy-id -i ~/.ssh/bastion_ansadmin.pem ansadmin@192.168.3.x
    ```
3. **Configura el archivo sudo para otorgar permisos de configuración.**

   Para otorgar permisos de configuración, sigue estos pasos:

   - Edita el archivo `/etc/sudoers` con un editor de texto como `vi` o `nano`:

     ```bash
     sudo vi /etc/sudoers
     ```

   - Agrega la siguiente línea al archivo para otorgar permisos:

     ```bash
     ansadmin ALL=(ALL) NOPASSWD: ALL
     ```

   Esto permite que el usuario `ansadmin` ejecute comandos `sudo` sin ingresar una contraseña.

4. **Instala Git.**

5. **Descarga el proyecto bastionweb.**

   Sigue estos pasos para instalar Git y descargar el proyecto:

   - Navega al directorio temporal:

     ```bash
     cd /tmp
     ```

   - Clona el repositorio de GitHub que contiene el proyecto `bastionweb`:

     ```bash
     sudo git clone https://github.com/lgeronimoM/bastionweb.git
     ```

   - Accede al directorio del proyecto:

     ```bash
     cd /tmp/bastionweb
     ```

   - Haz que el script de instalación sea ejecutable:

     ```bash
     sudo chmod u+x install.sh
     ```

   - Ejecuta el script de instalación:

     ```bash
     sudo ./install.sh
     ```

   - Inicia el servicio `bastion`:

     ```bash
     sudo systemctl start bastion
     ```

## Acceso Web
- **Usuario:** admin
- **Contraseña:** bastion
