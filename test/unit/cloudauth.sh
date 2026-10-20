#!/bin/sh

check() {
	${HAPROXY_PROGRAM} -vv | grep -E '^Unit tests list :' | grep -q "cloudauth"
}

run() {
	${HAPROXY_PROGRAM} -U cloudauth_iso_date || return 1
	# only built with the s3 provider
	if ${HAPROXY_PROGRAM} -vv | grep -E '^Unit tests list :' | grep -qw "cloudauth_s3_sts"; then
		${HAPROXY_PROGRAM} -U cloudauth_s3_sts || return 1
	fi
}

case "$1" in
	"check")
		check
	;;
	"run")
		run
	;;
esac
