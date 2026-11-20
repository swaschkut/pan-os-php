# pan-os-php config viewer (prototype): one image for the web part, the service, the job runner and the runs.
# Build context is the repository root - see ../docker-compose.yml:
#   docker compose -f utils/develop/config-viewer/docker-compose.yml up -d --build
ARG IMAGE=ubuntu:26.04
FROM docker:cli AS dockercli

FROM ${IMAGE}
ARG php_var="8.5"
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update --fix-missing \
  && apt-get install -y --fix-missing \
    tzdata \
    php$php_var-cli \
    php$php_var-curl \
    php$php_var-dom \
    php$php_var-mbstring \
    php$php_var-bcmath \
    php$php_var-yaml \
    php$php_var-sqlite3 \
    util-linux \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# docker client only (no daemon): used by the job runner to start one container per run
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /tools/pan-os-php
COPY lib ./lib
COPY phpseclib ./phpseclib
COPY git-php ./git-php
COPY utils ./utils
# utils/lib/UTIL.php loads the migration parser at start
COPY migration ./migration
COPY appid-toolbox ./appid-toolbox
COPY CHANGELOG.txt .

# the data directory: owned by the runtime user, so that a new volume mounted here gets the same owner
RUN echo 'include_path = "/usr/share/php:/tools/pan-os-php"' >> /etc/php/$php_var/cli/php.ini \
  && mkdir /data && chown ubuntu:ubuntu /data && chmod 700 /data

ENV PANOSPHP_VIEWER_DATA=/data
WORKDIR /tools/pan-os-php/utils/develop/config-viewer
ENTRYPOINT [ "/bin/bash", "/tools/pan-os-php/utils/develop/config-viewer/docker/start.sh" ]
CMD [ "web" ]
