#!/usr/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# (C) Copyright 2019-2022 Stephane Neveu
# (C) Copyright 2019-2022 Nicolas Bouchinet

set -o errexit -o nounset

disable_systemd(){
	systemctl stop keysas-backend.service || true
	systemctl disable keysas-backend.service || true
	systemctl daemon-reload
}

main() {
	disable_systemd

	files="
		/etc/systemd/system/keysas-backend.service
		/usr/bin/keysas-backend
	"

	dirs="
		/etc/systemd/system/keysas-backend.service.d/
		/var/local/tmp/
	"


	readonly files dirs 

	for file in ${files}; do
		[ -f "${file:-}" ] && rm -rf "${file}"
	done
	for dir in ${dirs}; do
		[ -d "${dir:-}" ] && rm -rf "${dir}"
	done

	echo "keysas-backend should be removed !"
}

main "$@"

