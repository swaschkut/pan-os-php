ARG IMAGE=ubuntu:26.04
FROM ${IMAGE}

#apt-cache search python3-mpmath
#apt-get install python3-mpmath
#python3-mpmath is already the newest version (1.2.1-3).
#Python 3.12.3
#unaffected version mpmath 1.3.0-1
#https://launchpad.net/ubuntu/+source/mpmath

ARG php_var="8.5"
ARG user_var="ubuntu"
ARG DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-c"]


RUN apt-get update --fix-missing \
  && apt-get install -y --fix-missing \
    tzdata \
    git \
    bash-completion \
    vim \
    inetutils-ping \
    inetutils-traceroute \
    php$php_var \
    php$php_var-curl \
    php$php_var-dom \
    php$php_var-mbstring \
    php$php_var-bcmath \
    php$php_var-yaml \
    php$php_var-ldap \
    python3 \
    python3-pandas \
    python3-bs4 \
    python3-xlsxwriter \
    python3-netaddr \
    python3-requests \
    python3-plotly \
    python3-pip \
    jq \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

#RUN pip3 install kaleido

WORKDIR /tools/pan-os-php

# Rechte direkt beim Kopieren setzen statt spaeter mit "chmod -R 777"
# (ein separates chmod -R dupliziert alle Dateien in einem neuen Layer)
COPY --chmod=777 appid-toolbox ./appid-toolbox
COPY --chmod=777 lib ./lib
COPY --chmod=777 phpseclib ./phpseclib
COPY --chmod=777 git-php ./git-php
COPY --chmod=777 utils ./utils
COPY --chmod=777 tests ./tests
COPY --chmod=777 migration ./migration
COPY --chmod=777 CHANGELOG.txt .


# PHP library of pan-os-php
RUN echo 'include_path = "/usr/share/php:/tools/pan-os-php"' >> /etc/php/$php_var/cli/php.ini \
  && chmod 777 /tools/pan-os-php \
  && ln -s /tools/pan-os-php/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php

USER $user_var

# Git-Konfiguration fuer den Laufzeit-User
RUN git config --global user.email "test@test.com" \
  && git config --global user.name "test"

# UTIL alias for pan-os-php
RUN cat /tools/pan-os-php/utils/alias.sh >> /home/$user_var/.bashrc \
  && cat /tools/pan-os-php/utils/bash_autocompletion/enable_bash.txt >> /home/$user_var/.bashrc

# Entrypoint script
WORKDIR /scripts
COPY docker/entrypoint.sh .

# Working dir for the app
VOLUME /share
WORKDIR /share


ENTRYPOINT [ "/bin/bash", "/scripts/entrypoint.sh" ]
