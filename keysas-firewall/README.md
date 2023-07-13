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
    - [ ] Allow authorization changes
  - Daemon
    - [X] Check report and files
    - [ ] Use CA certificate to check report certificate
    - [ ] Enforce system security policy
    - [ ] Check USB devices
  - Tray app
    - [X] Display files
    - [X] Display USB devices
    - [ ] Allow authorization changes
    