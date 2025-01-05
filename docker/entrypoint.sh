#!/usr/bin/env bash

export LDAP_HOST=$(awk -F "= " '/host = / {print $2}' /ska/config/config.ini | sed 's/"//g')
export LDAP_BIND_DN=$(awk -F "= " '/bind_dn = / {print $2}' /ska/config/config.ini | sed 's/"//g')
export LDAP_BIND_PW=$(awk -F "= " '/bind_password = / {print $2}' /ska/config/config.ini | sed 's/"//g')
export LDAP_DN_USER=$(awk -F "= " '/dn_user = / {print $2}' /ska/config/config.ini | sed 's/"//g')

# start cron
echo "Starting cron..."
service cron start

# set permissions
echo "Setting permissions..."
chown key-sync /ska/config/keys-sync*
chmod 600 /ska/config/key-sync*

# wait for database
echo "Waiting for database..."
sleep 5

# sync keys
echo "Syncing keys..."
/ska/scripts/syncd.php --user keys-sync

# show logs
echo "Showing logs..."
tail -f /var/log/keys/sync.log &

# start apache
echo "Starting apache..."
apache2-foreground
