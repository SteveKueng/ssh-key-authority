FROM php:7.2-apache

# Systemvariablen setzen
ENV SYSTEM=https://github.com/operasoftware/ssh-key-authority.git

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ADD cron /etc/cron.d/ldap-sync
RUN chmod 0644 /etc/cron.d/ldap-sync

RUN ln -s /usr/local/bin/php /usr/bin/php

# Erforderliche Pakete installieren
RUN apt-get update && \
    apt-get install -y \
        git \
        cron \
        default-libmysqlclient-dev \
        libldap2-dev \
        libssh2-1-dev \
        libmcrypt-dev && \
        docker-php-ext-install \
        ldap \
        mysqli \
        mbstring \
        pcntl
        
RUN pecl install ssh2-1.1.2 && \
        docker-php-ext-enable ssh2

# Verzeichnisse erstellen und Berechtigungen setzen
RUN mkdir -p /var/log/keys/ /run/php/ /ska/ && \
    chown -R www-data:www-data /var/log/keys/ /run/php/ /ska/

# Benutzer für die Synchronisation hinzufügen
RUN adduser --system --disabled-password keys-sync

# Repository klonen und Berechtigungen setzen
RUN git clone ${SYSTEM} /ska && \
    chown -R keys-sync:nogroup /ska/config

RUN a2enmod authnz_ldap
RUN a2enmod session
RUN a2enmod session_cookie
RUN a2enmod session_crypto
RUN a2enmod auth_form
RUN a2enmod request

# Apache konfigurieren
COPY ldap-docker.conf /etc/apache2/conf-enabled/ldap-docker.conf

RUN cat <<EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
    DocumentRoot /ska/public_html
    DirectoryIndex init.php
    FallbackResource /init.php

    <Directory /ska/public_html>
        AuthType Basic
        AuthName "SSH Key Authority"
        AuthBasicProvider docker

        AuthUserFile /dev/null
        Require valid-user
    </Directory>
</VirtualHost>
EOF

WORKDIR /ska/public_html

# Exponieren des Apache-Ports
EXPOSE 80

# Startbefehl für den Container
CMD ["/entrypoint.sh"]