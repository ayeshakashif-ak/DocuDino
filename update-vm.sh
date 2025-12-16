#!/bin/bash
cd /home/azureuser/DocuDino
git pull origin main
npm install
npm run build
pm2 restart all || pm2 start npm --name "docudino" -- start
