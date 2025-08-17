FROM php:7.4-apache

# Set system vars
ENV SYSTEM=https://github.com/SteveKueng/ssh-key-authority.git

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Provide php binary at /usr/bin/php
RUN ln -s /usr/local/bin/php /usr/bin/php

# Install required build/runtime packages
# - libonig-dev: needed for mbstring on PHP 7.4
# - libldap2-dev: needed for ldap extension
# - default-libmysqlclient-dev: needed for mysqli
# - build-essential, cmake, libssl-dev, git, wget: build deps (libssh2 + pecl/ssh2)
# - cron: used by your crontab
RUN apt-get update && \
    apt-get install -y \
        git \
        cron \
        default-libmysqlclient-dev \
        libldap2-dev \
        libonig-dev \
        build-essential \
        cmake \
        libssl-dev \
        wget && \
    rm -rf /var/lib/apt/lists/*

# Build latest libssh2 from source (links into /usr/local)
WORKDIR /usr/local/src
RUN git clone https://github.com/libssh2/libssh2.git && \
    cd libssh2 && \
    mkdir build && cd build && \
    cmake .. && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig

# Configure and install PHP extensions
# NOTE: ldap often needs an explicit libdir on Debian-based images
RUN docker-php-ext-configure ldap --with-libdir=lib/x86_64-linux-gnu && \
    docker-php-ext-install \
        ldap \
        mysqli \
        mbstring \
        pcntl

# Install php-ssh2 from PECL and enable it
RUN pecl install ssh2-1.3.1 && \
    echo "extension=ssh2.so" > /usr/local/etc/php/conf.d/ssh2.ini

# Create dirs and set permissions
RUN mkdir -p /var/log/keys/ /run/php/ /ska/ && \
    chown -R www-data:www-data /var/log/keys/ /run/php/ /ska/

# Add sync user
RUN adduser --system --disabled-password keys-sync

# Clone repo and set ownership for config
RUN git clone ${SYSTEM} /ska && \
    chown -R keys-sync:nogroup /ska/config

# Enable needed Apache modules
RUN a2enmod authnz_ldap \
    && a2enmod session \
    && a2enmod session_cookie \
    && a2enmod session_crypto \
    && a2enmod auth_form \
    && a2enmod request \
    && a2enmod headers \
    && a2enmod rewrite \
    && a2enmod setenvif

# Apache conf from build context
COPY ldap-docker.conf /etc/apache2/conf-enabled/ldap-docker.conf

# Configure default vhost (sauberer Heredoc, nichts escapen)
RUN cat >/etc/apache2/sites-available/000-default.conf <<'APACHECONF'
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
APACHECONF

# Install crontab
ADD cron /tmp/cron
RUN crontab /tmp/cron

WORKDIR /ska/public_html

EXPOSE 80

# Start command
CMD ["/entrypoint.sh"]
