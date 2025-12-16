#!/bin/bash
sudo apt update
sudo apt install -y git nodejs npm
cd /home/azureuser
git clone https://github.com/ayeshakashif-ak/DocuDino.git
cd DocuDino
npm install
npm run build
pm2 start npm --name "docudino" -- start
