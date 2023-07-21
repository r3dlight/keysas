# Keysas USB firewall

The keysas USB firewall is used on Windows client to control that:
 - USB devices connected have been enrolled in the system
 - That files on USB devices have been validated by a Keysas station

The firewall is composed of four elements:
 - In kernel space
   - A USB bus filter driver
   - A minifilter (driver to filter system call towards the filesystem)
 - In userspace
    - A daemon that supervise the two drivers and performs the checking based on the system security policy
    - A tray application to allow the end user to control the security settings

 This firewall is still a work in progress.
  - USB bus filter driver
    - [ ] Bus call interception
  - Minifilter
    - [X] System call interception and filtering
    - [X] Track per file context
    - [X] Allow authorization changes
    - [X] Filter file open and create operations
    - [X] Filter write operation
    - [ ] Clean code: check IRQL, check paging, check fastIO, check sparse file API, check all flags in the pre-op filters...
  - Daemon
    - [X] Check report and files
    - [X] Use CA certificate to check report certificate
    - [X] Enforce system security policy
    - [ ] Check USB devices
  - Tray app
    - [X] Display files
    - [~] Display USB devices
    - [X] Allow authorization changes
    - [X] Add drop down menu for authorization selection
    
System security policy is configured from a TOML file at the base of the Daemon directory.
The policy is configured with:
 - 'disable_unsigned_usb': if set to 'true' unsigned usb devices are allowed. No checks are performed on files on these devices.
 - 'allow_user_usb_authorization': if set to 'true' grant the user the ability to manualy allow unsigned USB devices. No checks are performed on files on these devices.
 - 'allow_user_file_read': if set to 'true' grant the user the ability to manualy allow read access to an unsigned file.
 - 'allow_user_file_write': if set to 'true' grant the user the ability to manualy allow write access to file on a USB device. 'allow_user_file_read' must also be set to true.
If parameters are missing from the configuration file they are considered to be set to 'false'.