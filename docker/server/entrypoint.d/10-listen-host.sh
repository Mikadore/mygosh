#!/bin/sh
set -eu

: "${MYGOSH_CONFIG_PATH:?}"
: "${MYGOSH_LISTEN_HOST:=0.0.0.0}"

escaped_host="$(printf '%s\n' "${MYGOSH_LISTEN_HOST}" | sed 's/[\/&]/\\&/g')"

if grep -Eq '^[[:space:]]*host[[:space:]]*=' "${MYGOSH_CONFIG_PATH}"; then
	sed -i -E "s|^[[:space:]]*host[[:space:]]*=.*$|host = \"${escaped_host}\"|" "${MYGOSH_CONFIG_PATH}"
else
	sed -i "/^\\[core\\]$/a host = \"${escaped_host}\"" "${MYGOSH_CONFIG_PATH}"
fi
