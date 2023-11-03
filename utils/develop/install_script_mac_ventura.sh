#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR=$USER
USER_FOLDER_PATH="/Users/"$USER
PHP_VAR="8.0"


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
&& brew install php@8.2 \
&& echo "" \
&& php -v \
&& echo "" \
&& echo "RUN echo 'include_path = "/usr/local/Cellar/php/8.2.12/share/php/pear:/Users/svenwaschkut/Documents/PAN-scripting/pan-os-php"' >> /opt/homebrew/etc/php/8.2/php.ini" \
&& echo "" \
&& echo "install GIT" \
&& brew install git \
&& echo "" \
&& echo "" \
&& echo "\"install BASH5\"" \
&& brew install bash \
&& echo "" \
&& echo "echo /opt/homebrew/bin/bash | sudo tee -a /etc/shells" \
&& echo "chpass -s /opt/homebrew/bin/bash svenwaschkut" \
&& echo "" \
&& echo "" \
&& brew install jq \
&& echo "" \
&& echo "" \
&& echo "eval '$(/opt/homebrew/bin/brew shellenv)'" \
&& echo "alias pan-os-php='php -r "require_once '"'"'utils/pan-os-php.php'"'"';" $@'" \
&& echo "echo "[ -f /opt/homebrew/etc/bash_completion ] && . /opt/homebrew/etc/bash_completion" >> ~/.bash_profile" \
&& echo "" \
&& echo "" \
&& echo "set user bash profile"   \
&& cat ${FOLDER_PATH}/utils/alias.sh >> ${USER_FOLDER_PATH}/.bash_profile \
&& echo "" \
&& echo "check if everything is successfully installed" \
&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo ""

cat .bash_profile

eval "$(/opt/homebrew/bin/brew shellenv)"

alias pan-os-php='php -r "require_once '"'"'utils/pan-os-php.php'"'"';" $@'

 [ -f /opt/homebrew/etc/bash_completion ] && . /opt/homebrew/etc/bash_completion