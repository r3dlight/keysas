#!/usr/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# (C) Copyright 2019-2022 Stephane Neveu
# (C) Copyright 2019-2022 Nicolas Bouchinet

set -o errexit -o nounset

disable_systemd(){
	systemctl stop keysas.service || true
	systemctl disable keysas.service || true
	systemctl disable keysas-in.service || true
	systemctl disable keysas-transit.service || true
	systemctl disable keysas-out.service || true
	systemctl daemon-reload
}

main() {
	disable_systemd

	files="
		/var/log/keysas-in
		/var/log/keysas-transit
		/var/log/keysas-out
		/etc/systemd/system/keysas.service
		/etc/systemd/system/keysas-in.service
		/etc/systemd/system/keysas-transit.service
		/etc/systemd/system/keysas-out.service
		/etc/keysas/keysas-in.conf
		/etc/keysas/keysas-transit.conf
		/etc/keysas/keysas-out.conf
		/usr/bin/keysas-in
		/usr/bin/keysas-transit
		/usr/bin/keysas-out
		/etc/apparmor.d/usr.bin.keysas-in
		/etc/apparmor.d/usr.bin.keysas-transit
		/etc/apparmor.d/usr.bin.keysas-out
		/etc/apparmor.d/local/usr.sbin.clamd
		/etc/systemd/system/clamav-daemon.socket
	"

	dirs="
		/etc/systemd/system/keysas-in.service.d/
		/etc/systemd/system/keysas-transit.service.d/
		/etc/systemd/system/keysas-out.service.d/
		/var/local/in
		/var/local/transit
		/var/local/out
		/run/diode-in
		/run/diode-out
		/usr/share/keysas
		/etc/keysas
	"

	users="
		keysas-out
		keysas-transit
		keysas-in
	"

	readonly files dirs users

	for file in ${files}; do
		[ -f "${file:-}" ] && rm -rf "${file}"
	done
	for dir in ${dirs}; do
		[ -d "${dir:-}" ] && rm -rf "${dir}"
	done
	for user in ${users}; do
		if getent passwd "${user}" >/dev/null ; then
			userdel "${user}" >/dev/null
		fi
		if getent group "${user}" >/dev/null ; then
			groupdel "${user}" >/dev/null
		fi
	done
	systemctl disable clamav-daemon.socket | true
	systemctl daemon-reload
	echo "Keysas should be removed !"
}

main "$@"

