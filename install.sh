#!/bin/bash

sudo yum clean all

sudo yum install epel-release -y

sudo yum install python3 python3-pip python3-devel gcc -y

sudo pip3 install --upgrade pip

sudo pip3 install virtualenv

sudo groupadd dnsweb

sudo useradd -s /usr/sbin/nologin udnsweb

sudo usermod -G dnsweb udnsweb

sudo mkdir -p /etc/dnsweb

sudo chown udnsweb.dnsweb /etc/dnsweb

sudo mkdir -p /var/log/dnsweb

sudo chown udnsweb.dnsweb /var/log/dnsweb

sudo python3 -m virtualenv /etc/dnsweb/venv

sudo cp main.py /etc/dnsweb/
sudo cp wsgi.py /etc/dnsweb/
sudo cp -r app /etc/dnsweb/
sudo cp properties.py /etc/dnsweb/
sudo cp README.md /etc/dnsweb/
sudo cp requirements.txt /etc/dnsweb/

source /etc/dnsweb/venv/bin/activate

sudo pip3 install -r /etc/dnsweb/requirements.txt

sudo echo -e "
[Unit]
Description=Gunicorn instance to serve myproject
After=network.target

[Service]
User=udnsweb
Group=dnsweb
WorkingDirectory=/etc/dnsweb
Environment="PATH=/etc/dnsweb/venv/bin"
ExecStart=/etc/dnsweb/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:4000 main:app

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/dnsweb.service

sudo systemctl daemon-reload