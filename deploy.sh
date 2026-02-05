#!/bin/sh

sudo -u www-data git pull

echo "build"

cat .env

go version

go build -buildvcs=false -o scanner ./cmd/scanner

echo "success"

sudo supervisorctl restart scanner-go

#sudo supervisorctl status
#sudo supervisorctl reread
#sudo supervisorctl update