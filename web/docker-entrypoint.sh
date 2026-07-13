#!/bin/sh
set -eu

api_port="${HOME_MESH_API_PORT:-18080}"

case "$api_port" in
  ''|*[!0-9]*)
    echo "HOME_MESH_API_PORT must be an integer between 1 and 65535" >&2
    exit 1
    ;;
esac

if [ "$api_port" -lt 1 ] || [ "$api_port" -gt 65535 ]; then
  echo "HOME_MESH_API_PORT must be an integer between 1 and 65535" >&2
  exit 1
fi

export HOME_MESH_API_PORT="$api_port"
envsubst '${HOME_MESH_API_PORT}' \
  < /etc/nginx/nginx.conf.template \
  > /tmp/nginx.conf

nginx -t -c /tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
