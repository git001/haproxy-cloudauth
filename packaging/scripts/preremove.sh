#!/bin/sh
# Stops and disables the service when the package is removed, not upgraded
set -e

# rpm: $1 = 0 on a removal, deb: "remove"
if [ "${1:-}" = "remove" ] || [ "${1:-}" = "0" ]; then
	if [ -d /run/systemd/system ]; then
		systemctl --no-reload disable --now haproxy-cloudauth.service >/dev/null 2>&1 || :
	fi
fi
