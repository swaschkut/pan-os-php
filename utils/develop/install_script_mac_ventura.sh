#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR=$USER
USER_FOLDER_PATH="/Users/"$USER
PHP_VAR="8.2"
HOMEBREW_PATH="/opt/homebrew"


echo "START \"install script for MACOS\"" \
&& echo "" \
&& echo "\"install HOMEBREW\"" \
&& echo "For MacOS Ventura, MacOS Monterey:" \
&& /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "\"install bash_autocompletion\"" \
&& brew install bash-completion \
&& echo "" \
&& echo "" \
&& brew install php@${PHP_VAR} \
&& echo "" \
&& php -v \
&& echo "" \
&& echo "" \
&& echo "set PHP include_path" \
&& echo 'include_path = '${FOLDER_PATH} >> ${HOMEBREW_PATH}/etc/php/${PHP_VAR}/php.ini \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "install GIT" \
&& brew install git \
&& echo "" \
&& echo "" \
&& mkdir -p /tools ; cd /tools \
&& echo "extract everything to /tools and rename it to pan-os-php" \
&& echo "" \
&& echo "INSTALLATION via GIT" \
&& GIT_SSL_NO_VERIFY=true git clone https://github.com/swaschkut/pan-os-php.git \
&& echo "" \
&& chmod -R 777 ${FOLDER_PATH} \
&& echo "" \
&& echo "" \
&& echo "\"install BASH5\"" \
&& brew install bash \
&& echo "" \
&& echo "" \
&& echo ${HOMEBREW_PATH}/bin/bash | sudo tee -a /etc/shells \
&& echo "chpass -s ${HOMEBREW_PATH}/bin/bash ${USER_VAR}" \
&& echo "" \
&& echo "" \
&& brew install jq \
&& echo "" \
&& echo "" \
&& echo "set user bash profile"   \
&& echo "eval '$(${HOMEBREW_PATH}/bin/brew shellenv)'" >> ~/.bash_profile \
&& echo "alias pan-os-php='php -r "require_once '"'"'utils/pan-os-php.php'"'"';" $@'" >> ~/.bash_profile \
&& echo "[ -f ${HOMEBREW_PATH}/etc/bash_completion ] && . ${HOMEBREW_PATH}/etc/bash_completion" >> ~/.bash_profile \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "set link for bash_completion" \
&& ln -s ${FOLDER_PATH}/utils/bash_autocompletion/pan-os-php.sh ${HOMEBREW_PATH}/etc/bash_completion.d/pan-os-php \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "check if everything is successfully installed" \
&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo ""