#!/bin/sh
set -eu

known_hosts_source="${HOME_MESH_SSH_KNOWN_HOSTS_SOURCE:-}"
if [ -n "$known_hosts_source" ]; then
  known_hosts_path=/tmp/home-mesh-known-hosts
  umask 077
  cp "$known_hosts_source" "$known_hosts_path"
  chmod 0600 "$known_hosts_path"
  export HOME_MESH_SSH_KNOWN_HOSTS_PATH="$known_hosts_path"
fi

exec /usr/local/bin/home-mesh-api "$@"
