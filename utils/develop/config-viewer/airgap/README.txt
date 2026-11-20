pan-os-php config viewer - installation without internet
=========================================================

Needs: Docker with the Compose plugin ("docker compose version" works). Nothing is downloaded.

Install / update
    ./install.sh
  Loads the images from images.tar.gz, asks the first time who uses the viewer, starts it and shows the address.
    1) only this computer       http://127.0.0.1:8080/
    2) other computers too      HTTPS with a name (DNS must point to this computer; ports 443 and 80);
                                certificate: own certificate authority of the viewer, your own cert.pem + key.pem,
                                or Let's Encrypt (internet needed)
  First start: the user "admin" and its password are shown once - change it under Account.
  Update: unpack the newer bundle into the same folder, ./install.sh again. The data stays (volume panosphp-viewer-data).

Every day
    ./panosphp-viewer status             running? address, licence, plug-ins
    ./panosphp-viewer stop | start | restart
    ./panosphp-viewer logs [web|service|jobs|proxy]
    ./panosphp-viewer password [user]    new password (forgotten / lost), shown once
    ./panosphp-viewer setup              answer the questions again, then ./panosphp-viewer restart

Licensed plug-ins (e.g. migration)
    ./panosphp-viewer plugin migration.ppp      add a plug-in package (also: plug-ins in the folder plugins/ of this bundle)
    ./panosphp-viewer license acme-2026.lic     install the licence (or in the browser: Account -> Licence)
    ./panosphp-viewer license                   show it

HTTPS with the own certificate authority
  Browsers warn until its certificate is trusted. Export it:
    docker compose -f docker-compose.yml -f docker-compose.https.yml exec proxy cat /data/caddy/pki/authorities/local/root.crt

Remove everything (also all data!)
    docker compose -f docker-compose.yml -f docker-compose.https.yml down -v

Settings are kept in .env next to panosphp-viewer. VERSION.txt names the image and the platform (linux/amd64 or
linux/arm64) of this bundle.
