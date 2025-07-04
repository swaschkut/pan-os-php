ARG IMAGE=ubuntu:25.04
FROM ${IMAGE}

#apt-cache search python3-mpmath
#apt-get install python3-mpmath
#python3-mpmath is already the newest version (1.2.1-3).
#Python 3.12.3
#unaffected version mpmath 1.3.0-1
#https://launchpad.net/ubuntu/+source/mpmath

ARG php_var="8.4"
ARG user_var="ubuntu"

SHELL ["/bin/bash", "-c"]


RUN DEBIAN_FRONTEND=noninteractive apt update --fix-missing \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing \
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
    python3 \
    python3-pandas \
    python3-bs4 \
    python3-xlsxwriter \
    python3-netaddr \
    python3-requests \
    python3-plotly \
    python3-pip \
	jq

#RUN pip3 install kaleido

WORKDIR /tools/pan-os-php

COPY appid-toolbox ./appid-toolbox
COPY lib ./lib
COPY phpseclib ./phpseclib
COPY git-php ./git-php
COPY utils ./utils
COPY tests ./tests
COPY iron-skillet ./iron-skillet
COPY migration ./migration


# PHP library of pan-os-php
RUN echo 'include_path = "/usr/share/php:/tools/pan-os-php"' >> /etc/php/$php_var/cli/php.ini \
  && chmod -R 777 /tools/pan-os-php

RUN ln -s /tools/pan-os-php/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php \
  && git config --global user.email=test@test.com user.name=test

USER $user_var
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
