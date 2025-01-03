#!/usr/bin/env bash

export LDAP_HOST=$(awk -F "= " '/host = / {print $2}' /ska/config/config.ini | sed 's/"//g')
export LDAP_BIND_DN=$(awk -F "= " '/bind_dn = / {print $2}' /ska/config/config.ini | sed 's/"//g')
export LDAP_BIND_PW=$(awk -F "= " '/bind_password = / {print $2}' /ska/config/config.ini | sed 's/"//g')
export LDAP_DN_USER=$(awk -F "= " '/dn_user = / {print $2}' /ska/config/config.ini | sed 's/"//g')

# start cron
service cron start

echo "Waiting for database..."
sleep 5
/ska/scripts/syncd.php --user keys-sync
apache2-foreground
