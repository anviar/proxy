#!/bin/bash -e

if [[ -z "${EXTERNAL_IP}" ]]; then
  EXTERNAL_IP="$(curl -s -4 "http://ifconfig.co")"
  if [[ -z "$EXTERNAL_IP" ]]; then
    echo "[F] Cannot determine external IP address."
    exit 3
  fi
fi

if [[ -z "${SECRET}" ]]; then
  echo "[+] Generating random SECRET..."
  SECRET=$(head -c 16 /dev/urandom | xxd -ps)
fi

REMOTE_SECRET=/etc/proxy-secret
curl -s https://core.telegram.org/getProxySecret -o ${REMOTE_SECRET} || {
  echo '[F] Cannot download proxy secret from Telegram servers.'
  exit 5
}

REMOTE_CONFIG=/etc/proxy-multi.conf
curl -s https://core.telegram.org/getProxyConfig -o ${REMOTE_CONFIG} || {
  echo '[F] Cannot download proxy configuration from Telegram servers.'
  exit 2
}

INTERNAL_IP=$(ip a show dev eth0|awk '/inet/{print $2}'|cut -d '/' -f 1)

echo "[I] tg://proxy?server=${EXTERNAL_IP}&port=${PORT:=443}&secret=${SECRET}"
exec mtproto-proxy -u nobody -p 8888 -H 443 -S ${SECRET} --nat-info ${INTERNAL_IP}:${EXTERNAL_IP} --aes-pwd ${REMOTE_SECRET} ${REMOTE_CONFIG} -M 1
