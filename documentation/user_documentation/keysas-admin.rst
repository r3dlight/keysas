
*************************
Keysas-admin application
*************************

.. note:: 

 **Keysas-admin** is a desktop application that allows you to manage your **Keysas** stations.
 You can manager your Public Key Infrastucture, register new stations, update them, sign USB devices and muche more.

SSH configuration
=================
First, start by creating a **Ed25519** private key and the associated public key on your computer
This keypair should only be dedicated to the administration of your Keysas stations. To do so, open a terminal and use the following command:

.. code-block:: shell-session
 
 ssh-keygen -m PEM -t ed25519 -f mykey

Then, set the path of both keys in the **"Admin configuration->SSH configuration"** menu

Generate a IKPQPKI
==================
To be able to sign your outgoing USB devices and to enroll new Keysas stations, you need to create a **IKPQPKI**
(Incredible Keysas (Hybrid) Post-Quantum Public Key Infrastucture). This is a PKI basically 😁
If you have never created a **IKPQPKI**, go to **"Admin configuration->IKPQPKI configuration"** and click on **"Create a new IKPQPKI"**

Provide the information requested to build your own custom PKI.
Be patient, this may take a while !

Enroll you Keysas stations
==========================
You can now start adding new **Keysas** stations in the **"Add a new Keysas"** menu providing a name and an IP address
When done, export the **public SSH** key by clicking the **"Export SSH pubkey"** button for each station added.

In the menu, go to **"Manage your registred stations"**, click on more, provide your **IKPQPKI** **password** then click on **"Enroll"**
Be patient, this may take some time !

Sign your outgoing USB keys
===========================
You can now start signing at least one USB device in **"Admin configuration->USB Signing"**
Type the **password** provided during your **IKPQPKI** creation, plug the USB key and wait !
Once again, be patient, this may take a while !
If your **Keysas** station has been previously enrolled, your signed USB key should be now recognized by the station.

You're now ready to go !