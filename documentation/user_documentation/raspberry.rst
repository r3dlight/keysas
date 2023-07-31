***************************************
Decontamination station for USB devices
***************************************


This is a 100% open-source decontamination station version for **Raspberry Pi v4** (ready-to-go), but you can of course build **Keysas** on Debian 12 (Bookworm) for both architecture (x86_64 or aarch64).

The provided image is based on the Keysas software and offers antivirus scanning as well as analysis based on +20000 pre-installed Yara rules. 
You can add new Yara rules as desired to increase the detection probability. 
You can also filter the types and maximum size of files to transfer as output. 
The code is entirely written in Rust, sandboxed, and follows the principle of least privilege.

.. note::
 Despite the care taken in the solution, there may still be some bugs during use. 
 Please don't hesitate to contact us to report any bugs, which will be addressed in future versions.

.. admonition:: What the Keysas station doesn't protect you from
  :class: warning

  Due to the nature and low cost of the Raspberry Pi platform, the Keysas station will obviously not be protected against USB-Killer. Protection mechanisms are deployed against BadUSB attacks, but the station may still be potentially vulnerable, under certain conditions, during the startup phase. It is strongly recommended in this case to control the output USB device inventory (as we will discuss later in this documentation) and, to some extent, the input device inventory as well.

Download
=========
- `keysas-sd-v2.1 <https://keysas.fr/download/rasp/keysas-sd-v2.1.tar.gz>`_ (`sha256 <https://keysas.fr/download/rasp/keysas-sd-v2.1.tar.gz.sha256>`_)
- `keysas-admin-v2.1 (GNU/Linux) <https://keysas.fr/download/keysas-admin/v2.1/keysas-admin_2.1_amd64.AppImage>`_ (`sha256 <https://keysas.fr/download/keysas-admin/v2.1/keysas-admin_2.1_amd64.AppImage.sha256>`_)


The downloaded image will automatically resize according to the size of your MicroSD card.
To copy the **Keysas** station image to your SD card:

.. code-block:: shell-session

 tar -xvzf keysas-sd-xxyy.tar.gz
 sudo dd if=raspberry_keysas_system_image.img of=/dev/sdX bs=1M status=progress


However, it is recommended to use the bmaptool software as follows:

.. code-block:: shell-session

 tar -xvzf keysas-sd-xxyy.tar.gz
 sudo bmaptool copy --bmap raspberry_keysas_system_image.img.bmap raspberry_keysas_system_image.img /dev/sdX 
  
Where sdX is the device detected by your computer for the SD card.

.. note::
 Due to the high read/write activity on the MicroSD card, it is strongly recommended to use high-performance cards.

Before getting started, you need to sign at least one output USB device (which will receive files considered safe). All unsigned USB storage devices will be considered default input devices (potentially containing malicious files).

.. danger::
 The output USB devices that you need to sign will be completely destroyed (MBR/Partitions, etc.) and rebuilt according to a specific model. There is no support for GPT partition tables at the moment.

Keysas-admin (Desktop client)
========================================================

The administration of Keysas stations, the signing, and revocation of output USB devices are greatly facilitated by using the keysas-admin application. 
It allows you to register your Keysas stations and manage them from an administration workstation.

Currently, only GNU/Linux administration workstations are supported. The downloads are available in the download section above.

To provide you with maximum security, the keysas-admin application is developed using the Tauri-app framework and exclusively uses Vue-JS 3 for the frontend and Rust language for the backend. 
Once installed, the application will automatically notify you of available updates and offer to install them.

The administration of **Keysas** stations works using the SSHv2 protocol. 
Therefore, you need to generate a dedicated pair of ed25519 asymmetric keys for Keysas station administration. 
To do this, open a terminal and enter the following command:

.. code-block:: shell-session

 ssh-keygen -m PEM -t ed25519 -f mykey

.. warning:: 
 The application currently does not support passphrase management or the PKCS#12 format. 
 Therefore, you need to enter an empty passphrase by pressing Enter. 
 Similarly, the enrollment and revocation features of Yubikeys are not supported by the application yet.

Once the key pair is generated, open the application and go to the **SSH configuration** tab. 
Enter the path to your public key and private key, and then validate. 
Finally, add your new Keysas station in the **Add a new Keysas** menu by retrieving the IP address displayed on your **Keysas** station. 
Then click on Manage your Keysas in the menu. 
Your new station should now appear there. 
Start by exporting your SSH public key by clicking on **Export SSH pubkey**.

.. warning:: 
 You must export your public key before using other available features. Otherwise, they will not work.

Once the SSH public key is exported, password-based SSH authentication will be disabled. You will need to authenticate using the SSH key pair previously created.

.. code-block:: shell-session

 ssh -i myprivatekey keysas@192.168.XX.YY (IP obtained via DHCP)

.. danger:: 
 During the first connection, before exporting the SSH public key, the default password is **Changeme007**.


Fido2 Authentication
=====================

By default, the **Keysas** station accepts transfers from any input devices. However, it is now possible for the administrator to configure the station to enforce user authentication using FIDO2.

.. note::
 Currently, only YubiKey 5 and 5c are supported for FIDO2 authentication. Support for other FIDO2-compatible keys will be added soon.

 
Enabling the Feature
---------------------

To activate the authentication feature, you need to connect to the **Keysas** station as a superadministrator. 
Please note that if you have exported your SSH public key using the "keysas-admin" application, password authentication is disabled. 
Therefore, you should connect using your private key.

.. code-block:: shell-session

 ssh -i mykey keysas@192.168.XX.YY (IP obtenue via DHCP)

Next, modify the configuration of the **keysas-io** system daemon:

.. code-block:: shell-session

 sudo vim /etc/systemd/system/keysas-io.service

Add the option -y true après ExecStart=/usr/bin/keysas-udev, as follows:

.. code-block:: shell-session

 ExecStart=/usr/bin/keysas-io -y

Reload the daemon configuration:

.. code-block:: shell-session

 sudo systemctl daemon-reload

Finally, restart the station to apply the configuration changes:

.. code-block:: shell-session

 sudo shutdown -r now

The **Keysas** station will now only accept transfers from authenticated users.

Initialisation de la Yubikey
----------------------------

Connect a YubiKey 5 to the station to configure it. Use the "keysas" account to perform this step:

.. code-block:: shell-session

 sudo /usr/bin/keysas-manage-yubikey -i

Please note that slot 2 of the YubiKey will be modified.

YubiKey Initialization
-----------------------

Connect a YubiKey 5 to the **Keysas** station to configure it. Use the "keysas-sign" account to perform this step:

.. code-block:: shell-session

 sudo /usr/bin/keysas-manage-yubikey -e -n Jean

Replace "John" with the name of the FIDO2 user. Modify it according to your needs.
Now, the FIDO2 key is ready for use.

Revoking a YubiKey
-------------------

If you ever need to revoke a YubiKey, simply connect it to the **Keysas** station and proceed as follows:

.. code-block:: shell-session

 sudo /usr/bin/keysas-manage-yubikey -r true


The YubiKey will start flashing. Press the button to confirm the revocation.

Using the Keysas Station
=========================


- In the top-right menu, you can find the status of the **Keysas** station as well as help ;
- If FIDO2 authentication is enabled, insert a registered YubiKey first ;
- Connect an input device (Any unsigned USB device should be recognized as an input device) ;
- If FIDO2 authentication is enabled, the YubiKey icon on the screen will turn green, and the button on the YubiKey should start blinking. Press the button to confirm the authentication ;
- Follow the on-screen instructions. Once the files start appearing in the output SAS, disconnect the input device ;
- Connect the signed output device after disconnecting the input device. ;


All configuration files are located in /etc/keysas/keysas-*.conf. 
It is possible to control a whitelist of file types (magic numbers) and set the maximum file size for transfer. Please refer to the official Keysas documentation for more information on the available options (https://keysas.fr/administration.html#keysas-transit).

Hardening of the station
=========================

The pre-built system image for Raspberry Pi 4 includes the following hardening features:

- Protections against BadUSB (the screen only works with the MIPI/DSI bus).
- Linux-hardened kernel with ClipOS v5 configuration.
- NFTables firewall (only the SSH port is exposed).
- Protection against SSH brute force attacks.
- Anti-bounce protection for SSH (SSH pivot).
- Specific configuration of the Linux kernel.
- Unsigned devices mounted as read-only (RO), NODEV, NOSUID, NOEXEC, NODEV.
- User sandboxing using Firejail.
- **Keysas** daemons sandboxed using Seccomp, Landlock, Namespaces, AppArmor.

For each transferred file, depending on the results of various scans, you may find the following extensions:

- .krp: Keysas report, contains various information about the scan
- .ioerror: the file has been corrupted (incomplete copy or disc full);




Updates
========

The **Keysas** station automatically installs the latest antivirus signatures and security updates when it has internet access. 
If the station cannot access the internet, updates can be performed using a local repository in the information system. 
Check the **FreshClam** documentation.
However, for now the "Keysas" daemons are not automatically updated and require the installation of new images that will be provided. 
It is important to backup configurations and generated keys.

Required Hardware
=================

`Official screen. <https://www.raspberrypi.com/products/raspberry-pi-touch-display/>`_

`Raspberry Pi 4 8Go RAM / model B. <https://www.raspberrypi.com/products/raspberry-pi-4-model-b/?variant=raspberry-pi-4-model-b-8gb>`_

`Power supply. <https://www.raspberrypi.com/products/type-c-power-supply/>`_

.. note:: 
  No data is or will be collected during your use of the **Keysas** station.
