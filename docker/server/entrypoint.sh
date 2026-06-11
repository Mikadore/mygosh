#!/bin/sh
set -eu

: "${MYGOSH_HOME:=/var/lib/mygosh}"
: "${MYGOSH_CONFIG_FILE:=mygosh.toml}"

mkdir -p "${MYGOSH_HOME}"

export MYGOSH_CONFIG_PATH="${MYGOSH_HOME}/${MYGOSH_CONFIG_FILE}"

cp /usr/share/mygosh/mygosh.toml "${MYGOSH_CONFIG_PATH}"

if [ -d /docker-entrypoint.d ]; then
	for hook in /docker-entrypoint.d/*; do
		[ -e "${hook}" ] || continue
		case "${hook}" in
			*.sh)
				if [ -x "${hook}" ]; then
					"${hook}"
				else
					/bin/sh "${hook}"
				fi
				;;
		esac
	done
fi

cd "${MYGOSH_HOME}"

exec "$@"
