#!/bin/sh
# Sets up app-srv-01 (Alpine Linux) as a small web application server.
# Run as root inside the VM, while the NAT (internet) adapter is connected:
#   wget http://192.168.56.1:8000/setup_app_server.sh && sh setup_app_server.sh
#
# Services (deliberately about a year old, so they have recent CVEs that the
# ML model scores; the lab is isolated on a host-only network):
#   80    Apache httpd 2.4.62
#   8080  Apache Tomcat 9.0.98
#   6379  Redis 7.2.4
set -e

echo "== Enabling the community repository and installing Docker"
sed -i 's|^#\(.*/community\)$|\1|' /etc/apk/repositories
apk update
apk add docker
rc-update add docker default
service docker start
sleep 5

# First tag that exists is used (Docker Hub tag names vary between releases)
pull_first() {
    for image in "$@"; do
        if docker pull "$image"; then echo "$image"; return 0; fi
    done
    echo "Could not pull any of: $*" >&2
    return 1
}

echo "== Downloading images"
HTTPD=$(pull_first httpd:2.4.62 | tail -n 1)
TOMCAT=$(pull_first tomcat:9.0.98 tomcat:9.0.98-jre17 tomcat:9.0.98-jdk17 | tail -n 1)
REDIS=$(pull_first redis:7.2.4 | tail -n 1)

echo "== Starting services"
docker rm -f web-httpd app-tomcat cache-redis 2>/dev/null || true
docker run -d --name web-httpd --restart unless-stopped -p 80:80 "$HTTPD"
docker run -d --name app-tomcat --restart unless-stopped -p 8080:8080 \
    -e CATALINA_OPTS="-Xms64m -Xmx160m" "$TOMCAT"
docker run -d --name cache-redis --restart unless-stopped -p 6379:6379 "$REDIS" \
    redis-server --protected-mode no

# The Tomcat image ships without a default page; restore it so the server
# shows its version (as a typical installation does) and a scan can read it
sleep 10
docker exec app-tomcat sh -c 'cp -r /usr/local/tomcat/webapps.dist/* /usr/local/tomcat/webapps/'

docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}"
echo
echo "Done. Back on Windows run:  scripts\\lab\\lab.ps1 isolate   (removes internet access)"
