#!/bin/bash

echo "Esta accion puede parcialmente afectar la aplicacion"
echo ""
echo "si esta seguro que deseas actualizar a la ultima version solo preciona enter"
echo "Esto puede tomar algunos minutos"
read -p "Preciona enter para continuar o ctrol 'C' para cancelar: " opcion

sudo yum install python3-pip python3-devel gcc -y

sudo rm -rf update

sudo git clone https://github.com/lgeronimoM/bastionweb.git update

sudo cp -f -a  update/main.py /etc/bastion/
sudo cp -f -a -r update/app /etc/bastion/
sudo cp -f -a update/properties.py /etc/bastion/
sudo cp -f -a update/README.md /etc/bastion/
sudo cp -f -a update/requirements.txt /etc/bastion/

sudo pip3 install -r /etc/bastion/requirements.txt

export FLASK_ENV=production

sudo echo -e "
[Unit]
Description=Proyecto bastion
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/etc/bastion
#Environment=PATH=/usr/local/bin
ExecStart=/usr/local/bin/uwsgi --http-socket :5000 --plugin python3 --module main:app --processes 4 --threads 4

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/bastion.service

sudo systemctl daemon-reload

sudo systemctl restart bastion