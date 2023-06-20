#!/usr/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# (C) Copyright 2019-2022 Stephane Neveu
# (C) Copyright 2019-2022 Nicolas Bouchinet

set -o errexit -o nounset

HOME_KEYSAS_IN="/var/local/in"
readonly HOME_KEYSAS_IN

HOME_KEYSAS_TRANSIT="/var/local/transit"
readonly HOME_KEYSAS_IN

HOME_KEYSAS_OUT="/var/local/out"
readonly HOME_KEYSAS_OUT

U_KEYSAS_IN="keysas-in"
readonly U_KEYSAS_IN

U_KEYSAS_OUT="keysas-out"
readonly U_KEYSAS_OUT

U_KEYSAS_TRANSIT="keysas-transit"
readonly U_KEYSAS_TRANSIT

# Create keysas-in, keysas-transit and keysas-out users if necessary.
add_users() {
	if ! getent passwd $U_KEYSAS_IN >/dev/null ; then
		useradd -r -M --shell /bin/false -d $HOME_KEYSAS_IN $U_KEYSAS_IN
		install -d -m 0750 -o $U_KEYSAS_IN -g $U_KEYSAS_IN $HOME_KEYSAS_IN
	fi
	if ! getent passwd $U_KEYSAS_TRANSIT >/dev/null ; then
		useradd -r -M --shell /bin/false -d $HOME_KEYSAS_TRANSIT -G $U_KEYSAS_IN $U_KEYSAS_TRANSIT
		install -d -m 0750 -o $U_KEYSAS_TRANSIT -g $U_KEYSAS_TRANSIT $HOME_KEYSAS_TRANSIT
	fi
	if ! getent passwd $U_KEYSAS_OUT >/dev/null ; then
		useradd -r -M --shell /bin/false -d $HOME_KEYSAS_OUT -G $U_KEYSAS_TRANSIT $U_KEYSAS_OUT
		install -d -m 0750 -o $U_KEYSAS_OUT -g $U_KEYSAS_OUT $HOME_KEYSAS_OUT
	fi
}

# Install ELF binaries in /usr/bin/.
install_bin() {
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-in" ]; then
			install -v -o $U_KEYSAS_IN -g $U_KEYSAS_IN -m 0500 ../bin/keysas-in /usr/bin/
		else
			echo "Binary ../bin/keysas-in cannot be found !"
		fi
	fi
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-transit" ]; then
			install -v -o $U_KEYSAS_TRANSIT -g $U_KEYSAS_TRANSIT -m 0500 ../bin/keysas-transit /usr/bin/
		else
			echo "Binary ../bin/keysas-transit cannot be found !"
		fi
	fi
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-out" ]; then
			install -v -o $U_KEYSAS_OUT -g $U_KEYSAS_OUT -m 0500 ../bin/keysas-out /usr/bin/
		else
			echo "Binary ../bin/keysas-out cannot be found !"
		fi
	fi
}

# Install systemd units.
install_systemd_units(){
	if [ -d "/etc/systemd/system/" ]; then
		install -v -o root -g root -m 0644 debian/keysas.service /etc/systemd/system/keysas.service
		install -v -o root -g root -m 0644 debian/keysas-in.service /etc/systemd/system/keysas-in.service
		install -v -o root -g root -m 0644 debian/keysas-transit.service /etc/systemd/system/keysas-transit.service
		install -v -o root -g root -m 0644 debian/keysas-out.service /etc/systemd/system/keysas-out.service
		install -v -o root -g root -m 0644 debian/clamav-daemon.socket /etc/systemd/system/clamav-daemon.socket

		if [ ! -d "/etc/systemd/system/keysas-in.service.d/" ]; then
			install -d -m 0750 -o root -g root /etc/systemd/system/keysas-in.service.d/
			if [ -f debian/keysas-in.security ]; then
				install -v -o root -g root -m 0644 debian/keysas-in.security /etc/systemd/system/keysas-in.service.d/security.conf
			fi
		fi
		if [ ! -d "/etc/systemd/system/keysas-transit.service.d/" ]; then
			install -d -m 0750 -o root -g root /etc/systemd/system/keysas-transit.service.d/
			if [ -f debian/keysas-transit.security ]; then
				install -v -o root -g root -m 0644 debian/keysas-transit.security /etc/systemd/system/keysas-transit.service.d/security.conf
			fi
		fi
		if [ ! -d "/etc/systemd/system/keysas-out.service.d/" ]; then
			install -d -m 0750 -o root -g root /etc/systemd/system/keysas-out.service.d/
			if [ -f debian/keysas-out.security ]; then
				install -v -o root -g root -m 0644 debian/keysas-out.security /etc/systemd/system/keysas-out.service.d/security.conf
			fi
		fi
	else
		echo "Path /etc/systemd/system/ not found, this system isprobably not using systemd !"
	fi
}

# Install Keysas config files.
install_config() {
	if [ ! -d "/etc/keysas" ]; then
		echo "Creating /etc/keysas directory."
		install -d -m 0755 -o root -g root /etc/keysas
	fi
	if [ -d "/etc/keysas/" ]; then
		echo "Installing configuration files for keysas."
		install -v -o $U_KEYSAS_IN -g $U_KEYSAS_IN -m 0600 debian/keysas-in.default /etc/keysas/keysas-in.conf
		install -v -o $U_KEYSAS_TRANSIT -g $U_KEYSAS_TRANSIT -m 0600 debian/keysas-transit.default /etc/keysas/keysas-transit.conf
		install -v -o $U_KEYSAS_OUT -g $U_KEYSAS_OUT -m 0600 debian/keysas-out.default /etc/keysas/keysas-out.conf
	fi
	if [ -d "/etc/sudoers.d "]; then
		install -v -o root -g root -m 0644 debian/keysas-sudoconfig /etc/sudoers.d/010_keysas
	fi
}

# Install apparmor profiles.
install_apparmor_profiles() {
	if [ -d "/etc/apparmor.d/" ]; then
		echo "Installing Apparmor policies:"
		install -v -o root -g root -m 0644 debian/usr.bin.keysas-in /etc/apparmor.d/usr.bin.keysas-in
		install -v -o root -g root -m 0644 debian/usr.bin.keysas-transit /etc/apparmor.d/usr.bin.keysas-transit
		install -v -o root -g root -m 0644 debian/usr.bin.keysas-out /etc/apparmor.d/usr.bin.keysas-out
		install -v -o root -g root -m 0644 debian/usr.sbin.clamd /etc/apparmor.d/local/usr.sbin.clamd
	else
		echo "WARNING: Directory /etc/apparmor.d/ not found ! Cannot install Apparmod policies..."
	fi
	if [ -x "/usr/sbin/apparmor_parser" ]; then
		echo "Applying Apparmor policies !"
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.keysas-in
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.keysas-transit
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.keysas-out
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd
	else
		echo "WARNING: Cannot find /usr/sbin/apparmor_parser !"
		echo "WARNING: Will not apply new Apparmor policies for keysas !"
	fi
}

# Set ACLs on directories.
set_acls(){
	if [ -d "$HOME_KEYSAS_IN" ]; then
		setfacl -b $HOME_KEYSAS_IN
		setfacl -m u:clamav:rx,g:$U_KEYSAS_IN:rwx $HOME_KEYSAS_IN
	fi
	if [ -d "$HOME_KEYSAS_TRANSIT" ]; then
		setfacl -b $HOME_KEYSAS_TRANSIT
		setfacl -m g:$U_KEYSAS_TRANSIT:rwx $HOME_KEYSAS_TRANSIT
	fi
	if [ -d "$HOME_KEYSAS_OUT" ]; then
		setfacl -b $HOME_KEYSAS_OUT
		setfacl -m g:$U_KEYSAS_OUT:rwx $HOME_KEYSAS_OUT
	fi
}

# Install a simple "demo" Yara rule.
install_yara_rule(){
	if [ ! -d "/usr/share/keysas/" ]; then
		echo "Installing a minimal YARA index.yar in /usr/share/keysas/"
		install -d -m 0755 -o root -g root /usr/share/keysas/
		install -d -m 0755 -o root -g root /usr/share/keysas/rules
		install -v -m 0644 -o root -g root  yara/index.yar /usr/share/keysas/rules/index.yar
	fi
}

# Enable systemd units.
enable_systemd() {
	echo "Reloading units..."
	systemctl stop clamav-daemon
	systemctl daemon-reload
	echo "Enabling keysas system in systemd..."
	systemctl enable clamav-daemon.socket
	systemctl enable keysas-in.service
	systemctl enable keysas-out.service
	systemctl enable keysas-transit.service
	systemctl enable keysas.service --now | true
	systemctl restart clamav-daemon
}

main() {
	# Call the above functions to perform the installation.
	add_users
	install_bin
	install_systemd_units
	install_config
	#install_apparmor_profiles
	set_acls
	install_yara_rule
	enable_systemd

	# Now let's try to be more verbose for the end users
	cat <<-EOF
	  _                  _____       _      _          _
  o         o/                                                      
 <|>       /v                                                       
 / >      />                                                        
 \o__ __o/      o__  __o    o      o    __o__   o__ __o/      __o__ 
  |__ __|      /v      |>  <|>    <|>  />  \   /v     |      />  \  
  |      \    />      //   < >    < >  \o     />     / \     \o     
 <o>      \o  \o    o/      \o    o/    v\    \      \o/      v\    
  |        v\  v\  /v __o    v\  /v      <\    o      |        <\   
 / \        <\  <\/> __/>     <\/>  _\o__</    <\__  / \  _\o__</   
                               /                                    
                              o                                     
       Core                 __/>                                     
	
	EOF
	echo "Installation completed !"

	INGID=$(getent group $U_KEYSAS_IN | awk -F: '{printf "%d\n", $3}')
	readonly INGID

	OUTGID=$(getent group $U_KEYSAS_OUT | awk -F: '{printf "%d\n", $3}')
	readonly OUTGID

	cat <<-EOF
		-|>- You can now create new users belonging to group keysas-in
		     to be able to deposit files into /var/local/in/
		     sudo adduser  --home /var/local/in --gid $INGID untrusted_user
		-|>- You also need to create new users belonging to group keysas-out
		     to be able to retrieve files from /var/local/out/
		     sudo adduser  --home /var/local/out --gid $OUTGID trusted_user
	EOF
}

main "$@"
 
