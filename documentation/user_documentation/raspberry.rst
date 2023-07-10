***************************************
Decontamination station for USB devices
***************************************


This is a 100% open-source decontamination station version for **Raspberry Pi v4**.

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
- `keysas-sd-v1.2 <https://keysas.fr/download/rasp/keysas-sd-v1.2.tar.gz>`_ (`sha256 <https://keysas.fr/download/rasp/keysas-sd-v1.2.tar.gz.sha256>`_)
- `keysas-admin-v0.1.2 (GNU/Linux) <https://keysas.fr/download/keysas-admin/v0.1.2/keysas-admin_0.1.2_amd64.AppImage>`_ (`sha256 <https://keysas.fr/download/keysas-admin/v0.1.2/keysas-admin_0.1.2_amd64.AppImage.sha256>`_)
- `keysas-admin-v0.1.2 (Windows) <https://keysas.fr/download/keysas-admin/v0.1.2/keysas-admin_0.1.2_x64_en-US.msi>`_ (`sha256 <https://keysas.fr/download/keysas-admin/v0.1.2/keysas-admin_0.1.2_x64_en-US.msi.sha256>`_)

The downloaded image will automatically resize according to the size of your MicroSD card.
To copy the white station image to your SD card:

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

Keysas-admin (Client lourd pour postes d'administration)
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
 Similarly, the enrollment and revocation features of Yubikeys are not yet supported by the application.

Once the key pair is generated, open the application and go to the **SSH configuration** tab. 
Enter the path to your public key and private key, and then validate. 
Finally, add your new Keysas white station in the **Add a new Keysas** menu by retrieving the IP address displayed on your Keysas white station. 
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


Signer un périphérique USB de sortie manuellement via SSH
=========================================================

Connexion à la station blanche
------------------------------

L'image fournie est basée sur une distribution GNU/Linux Debian 11 (Bullseye) toujours en cours de durcissement. Le DHCP est activé par défaut: Référez-vous à votre équipement réseau pour obtenir l'adresse IP obtenue par la station blanche après son démarrage.

Afin de prémunir la station blanche d'attaques de type BadUSB, seuls les périphériques USB de type "stockage de masse" comme les clés ou disques durs USB sont reconnus par la station blanche.
Pour signer un périphérique USB de sortie, il faut donc absolument se connecter via SSH sur la station blanche:

.. code-block:: shell-session

 ssh keysas-sign@192.168.XX.YY (IP obtenue via DHCP)

.. warning:: 
 Le mot de passe par defaut est **Changeme**. Il conviendra de modifier ce dernier dès la première utilisation en le remplacant par un mot de passe robuste avec la commande **passwd**.
 L'utilisateur **keysas-sign** est privilégié uniquement lorsque de l'utilisation des commandes **keysas-sign** et **keysas-manage-yubikey**.

Génération des clés de signature
--------------------------------

On va générer maintenant une paire de clés asymétriques qui servira à signer et vérifier les périphériques sortants:

.. code-block:: shell-session

 sudo /usr/bin/keysas-sign --generate=true --password=Toto007
 sudo chmod 600 /etc/keysas/keysas.priv
 sudo chattr +i /etc/keysas/keysas.priv

.. warning::

 Il est très important de remplacer le mot de passe dans la ligne de commande par le votre :)

.. danger::
 Cette bi-clé ne doit être générée qu'une seule fois à l'initialisation de la station blanche. Le remplacement de cette bi-clé
 entrainera l'échec de la vérification de la signature de toutes les périphériques USB déjà signés. Par défaut, les clés privées
 et publiques sont enregistrées dans /etc/keysas/. Il est important de sauvegarder ces clés dans un endroit sécurisé.

Signature d'un périphérique USB
-------------------------------

Une fois la paire de clés correctement générée, éxecutez la commande suivante:

.. code-block:: shell-session

 sudo /usr/bin/keysas-sign --watch=true

Brancher maintenant le périphérique usb de sortie à signer sur la station blanche. Ce périphérique devra être vide de tout fichier afin d'éviter des transferts non désirés.

Pressez Ctrl+C et copier/coller la ligne qui apparait dans le terminal en la modifiant avec le mot de passe que 
vous avez choisi pour générer la paire de clés précédemment. Par exemple:

.. code-block:: shell-session

 sudo /usr/bin/keysas-sign -device=/dev/sda --sign=true --password=Toto007 --vendorid=0951 --modelid=160b --revision=1.00 --serial=Kingston_DataTraveler_2.0_0019E000B4625C8B0A070016-0:0

Le nouveau périphérique USB devrait être maintenant correctement signé et formaté en fat32. Vous pouvez bien entendu reformater le périphérique avec tout autre système de fichier supporté par la station blanche (ext2, ext3, ext4, fat32, exfat, ntfs)

.. note::
 Répetez cette procédure avec l'ensemble des périphériques USB que vous souhaitez utiliser en tant que périphériques de sortie.


Une fois l'opération terminée, débranchez le(s) périphérique's) et rebranchez-le(s) afin de s'assurer qu'il(s) est(sont) bien reconnu(s) comme périphérique(s) de sortie.


Authentification avec fido2
===========================

Par défaut, la station blanche **Keysas** accepte les analyses à partir de n'importe quels périphériques d'entrée. 
Il est désormais possible pour l'administrateur de configurer la station blanche pour forcer une authentification des utilisateurs via Fido2.

.. note::
 Pour l'heure seules les clés **Yubikey 5 et 5c** sont prises en charge. D'autres types de clés compatibles **Fido2** seront bientôt supportées.

 
Activation de la fonctionnalité
-------------------------------

Pour activer la fonctionnalité d'authentification, il faut se connecter à la station blanche en tant que superadministrateur. Prenez note que si vous avez exporter votre clé SSH publique depuis l'application **keysas-admin**, l'authentification par mot de passe est désactivée. Il faudra donc se connecter en utilisant votre clé privée.

.. code-block:: shell-session

 ssh keysas@192.168.XX.YY (IP obtenue via DHCP)

.. danger:: 
 Le mot de passe par defaut est **Changeme007**. Il conviendra de modifier ce dernier dès la première utilisation en le remplacant par un mot de passe robuste avec la commande **passwd**.
 L'utilisateur **keysas** est totalement privilégié, l'utilisation de ce compte "superadmin" est donc critique et ne doit être employé que pour
 des tâches importantes d'administration ou pour modifier la configuration de la station blanche. 

Modifier ensuite la configuration du démon système **keysas-udev**:

.. code-block:: shell-session

 sudo vim /etc/systemd/system/keysas-udev.service

Puis ajouter l'option -y true après ExecStart=/usr/bin/keysas-udev, comme suit:

.. code-block:: shell-session

 ExecStart=/usr/bin/keysas-udev -y

Recharger la configuration du démon:

.. code-block:: shell-session

 sudo systemctl daemon-reload

Enfin, il ne vous reste plus qu'à redémarrer la station blanche pour activer la configuration:

.. code-block:: shell-session

 sudo shutdown -r now

La station blanche **Keysas** n'accepte désormais plus que les transferts d'utilisateurs authentifiés.

Initialisation de la Yubikey
----------------------------

Brancher une Yubikey 5 sur la station blanche pour la configurer et en vous connectant avec le compte **keysas-sign**:

.. code-block:: shell-session

 sudo /usr/bin/keysas-manage-yubikey -i

Pour information, le slot 2 de la Yubikey sera modifié.

Enregistrement de la Yubikey
----------------------------

Enregistrons maintenant la nouvelle Yubikey pour l'authentification d'un utilisateur de confiance:

.. code-block:: shell-session

 sudo /usr/bin/keysas-manage-yubikey -e -n Jean

**Jean** correspond au nom de l'utilisateur de la clé **Fido2**. Il conviendra donc de la modifier en fonction de votre besoin.
C'est terminé, la clé **Fido2** est maintenant opérationnelle. 

Révoquation d'une Yubikey
-------------------------

Si un jour cette clé doit être révoquée, il suffit de la brancher sur la station blanche et de procéder ainsi:

.. code-block:: shell-session

 sudo /usr/bin/keysas-manage-yubikey -r true


La Yubikey se met à clignoter, appuyer alors sur le bouton pour valider la révocation.

Utilisation de la station blanche
=================================


- Dans le menu en haut à droite, vous trouverez l'état de la station blanche ainsi que l'aide;
- Si l'authentification fido2 est activée: branchez d'abord une **Yubikey** enregistrée;
- Brancher un périphérique d'entrée (Tout périphérique USB non signé devrait être reconnue comme périphérique d'entrée) ;
- Si l'authentification fido2 est activée: L'icône de la Yubikey passe en vert sur l'écran et le bouton sur la **Yubikey** doit clignoter, appuyer dessus pour valider l'authentification;
- En suivant les instructions à l'écran et une fois les fichiers commençant à apparaitrent dans le sas de sortie, débrancher le périphérique d'entrée ;
- Brancher le périphérique de sortie signé une fois le périphérique d'entrée debranché ;

Si besoin, plusieurs périphériques d'entrée peuvent être utilisés à la suite avant de brancher le périphérique de sortie.

Tous les fichiers de configuration se situent dans /etc/keysas/keysas-\*.conf. Il est notamment possible de contrôler une liste blanche de types de fichers (magic numbers) ainsi que la taille maximale des fichiers à transférer. Veuillez-vous référer à la documentation officielle de Keysas pour plus d'information sur les différentes options (https://keysas.fr/administration.html#keysas-transit).


Durcissement de la station blanche
==================================

L'image système prête à l'emploi pour Raspberry Pi 4 dispose des fonctionnalités de durcissement suivantes:

- Des protections contre BadUSB (l'écran marche uniquement avec le bus MIPI/DSI); 
- Un noyau linux-hardened avec la configuration de ClipOS v5;
- Un firewall NFTables (seul le port SSH est exposé) ;
- Une protection contre le bruteforce SSH ;
- Une protection anti-rebond SSH (pivot SSH) ;
- Un paramètrage spécifique du noyau Linux ;
- Montage des périphériques non signés en RO, NODEV, NOSUID, NOEXEC, NODEV ;
- Kiosk utilisateur sandboxé via Firejail;
- Démons "keysas" sandoxés plusieurs fois (Seccomp, Landlock, Namespaces, Apparmor).

Tous les fichiers transférés dans la station blanche sont automatiquement renommé avec un horodatage. 
Pour chaque fichier transféré, vous pourrez éventuellement trouver, en fonction des résultats des différents scans, les extensions suivantes:

- .sha256: Contient le sha256 digest du fichier transféré;
- .antivirus: le fichier a été détecté par l'antivirus comme malveillant. Le fichier original n'est donc plus disponible;
- .forbidden: l'extension et le magic number ne correspondent pas ou est interdit par l'administrateur;
- .yara: Le moteur Yara a détecté un fichier potentiellement malveillant. Le fichier peut être transféré ou non suivant la configuration de l'administrateur. Par défaut, le fichier est supprimé;
- .tooBig: La taille du fichier est supérieure à celle fixée par l'administrateur. Le fichier n'est pas transféré;
- .failed: Un fichier n'a pas été tranféré complétement (erreur d'entrée/sortie lors de l'arrachage prématuré d'une clé par exemple).



Mises à jour
============

La station blanche installe automatique les dernières signatures antivirales et les mises à jour de sécurité du système lorque celle-ci peut accéder à internet.
Si la station blanche ne peut accéder à internet, il est tout à fait possible d'effectuer les mises à jours via un dépôt local au système d'information.
Les démons "Keysas" ne sont, quant à eux, pas automatiquement mis à jour et nécessitent pour le moment l'installation des nouvelles images qui seront misent à disposition.
Il conviendra donc de faire une sauvegarde des configurations et des clés générées.

Matériel nécessaire
===================

`L'écran officiel. <https://www.raspberrypi.com/products/raspberry-pi-touch-display/>`_

`Le Raspberry Pi 4 8Go de RAM / modèle B. <https://www.raspberrypi.com/products/raspberry-pi-4-model-b/?variant=raspberry-pi-4-model-b-8gb>`_

`L'alimentation. <https://www.raspberrypi.com/products/type-c-power-supply/>`_

.. note:: 
  Aucune donnée n'est et ne sera jamais collectée lors de votre utilisation de la station blanche.

