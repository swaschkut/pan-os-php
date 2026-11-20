pan-os-php config viewer - installation without internet
=========================================================

Needs: Docker with the Compose plugin ("docker compose version" works). Nothing is downloaded.

Install / update
    ./install.sh
  loads the images from images.tar.gz and starts the viewer: http://127.0.0.1:8080/ (this computer only).
  First start: the script prints the user "admin" and its password once - change it under Account.
  Update: unpack the newer bundle, ./install.sh again. The data stays (volume panosphp-viewer-data).

For several users (HTTPS)
    VIEWER_DOMAIN=viewer.example.com ./install.sh
  VIEWER_DOMAIN is the name the users type into the browser (DNS must point to this computer; ports 443 and 80).
  Certificate:
    default           the proxy makes its own CA. Browsers warn until its certificate is trusted. Export it:
                      docker compose -f docker-compose.yml -f docker-compose.https.yml exec proxy \
                          cat /data/caddy/pki/authorities/local/root.crt
    own certificate   put cert.pem and key.pem into docker/certs/ and start with
                      VIEWER_TLS="/certs/cert.pem /certs/key.pem" VIEWER_DOMAIN=... ./install.sh

Stop / remove
    docker compose -f docker-compose.yml -f docker-compose.https.yml down        stop (data stays)
    docker compose -f docker-compose.yml -f docker-compose.https.yml down -v     stop and delete all data

Other settings: VIEWER_PORT (default 8080, without HTTPS), VIEWER_ADMIN_USER / VIEWER_ADMIN_PASSWORD (first start).
VERSION.txt names the image and the platform (linux/amd64 or linux/arm64) of this bundle.
