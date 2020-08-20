#!/bin/bash

sudo yum clean all

sudo yum install epel-release -y

sudo yum install ansible python3 python3-pip python3-devel gcc -y

sudo pip3 install --upgrade pip

sudo pip3 install virtualenv

sudo groupadd bastion

sudo useradd bastion -s /usr/sbin/nologin -g bastion

sudo mkdir -p /etc/bastion

sudo mkdir -p /etc/bastion/db

sudo mkdir -p /var/log/bastion

sudo cp app/db/data.db /etc/bastion/db/

sudo cp main.py /etc/bastion/
sudo cp -r app /etc/bastion/
sudo cp properties.py /etc/bastion/
sudo cp README.md /etc/bastion/
sudo cp requirements.txt /etc/bastion/

sudo chown bastion.bastion /var/log/bastion -R
sudo chown bastion.bastion /etc/bastion -R

export FLASK_ENV=production

echo "host_key_checking = False" >> /etc/ansible/ansible.cfg

sudo pip3 install -r /etc/bastion/requirements.txt

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