#!/usr/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# (C) Copyright 2019-2022 Stephane Neveu

set -o errexit -o nounset

U_KEYSAS="root"
readonly U_KEYSAS

# Install ELF binaries in /usr/bin/.
install_bin() {
	if [ -d "/usr/bin" ]; then
		if [ -f "../bin/keysas-backend" ]; then
			install -v -o $U_KEYSAS -g $U_KEYSAS -m 0500 ../bin/keysas-backend /usr/bin/
		else
			echo "Binary ./bin/keysas-backend cannot be found !"
		fi
	fi
}

# Install systemd units.
install_systemd_units(){
	if [ -d "/etc/systemd/system/" ]; then
		install -v -o root -g root -m 0644 debian/keysas-backend.service /etc/systemd/system/keysas-backend.service
		if [ ! -d "/etc/systemd/system/keysas-backend.service.d/" ]; then
			install -d -m 0750 -o root -g root /etc/systemd/system/keysas-backend.service.d/
			if [ -f debian/keysas-backend.security ]; then
				install -v -o root -g root -m 0644 debian/keysas-backend.security /etc/systemd/system/keysas-backend.service.d/security.conf
			fi
		fi
	else
		echo "Path /etc/systemd/system/ not found, this system is probably not using systemd !"
	fi
}


# Install apparmor profiles.
install_apparmor_profiles() {
	if [ -d "/etc/apparmor.d/" ]; then
		echo "Installing Apparmor policies:"
		install -v -o root -g root -m 0644 debian/usr.bin.keysas-backend /etc/apparmor.d/usr.bin.keysas-backend
	else
		echo "WARNING: Directory /etc/apparmor.d/ not found ! Cannot install Apparmod policies..."
	fi
	if [ -x "/usr/sbin/apparmor_parser" ]; then
		echo "Applying Apparmor policies !"
		/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.keysas-backend
	else
		echo "WARNING: Cannot find /usr/sbin/apparmor_parser !"
		echo "WARNING: Will not apply new Apparmor policies for keysas !"
	fi
}

# Enable systemd units.
enable_systemd() {
	echo "Enabling keysas-backend in systemd..."
	systemctl enable keysas-backend.service
	systemctl start keysas-backend.service
}

install_utils() {
		if [ -d "/var/local/" ]; then
			install -d -m 0750 -o root -g root /var/local/tmp/
		fi
}

main() {
	# Call the above functions to perform the installation.
	install_bin
	install_systemd_units
	#install_config
	install_utils
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
         Backend           __/>                                     
	
	EOF
	echo "Installation completed !"

}

main "$@"
 
