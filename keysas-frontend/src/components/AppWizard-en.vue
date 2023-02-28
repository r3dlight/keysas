<template>
  <div class="container">
    <div class="row">
      <div class="col-sm-12">
      <section id="no-signed-key">
<h1>Congratulations and welcome to Keysas !</h1>
<div class="callout callout-info">
If this is your first time using the Keysas station you should first sign a USB key in order before going further.<br>
This tutorial will show you how to process. You will be able to display it anytime in the future using the menu.
</div>
<h2>How to create a USB device for output ?</h2>
<section id="connexion-a-la-station-blanche">
<h3>1 - Connect to your Keysas station</h3>
<p>The operating system is based on a hardened GNU/Linux Debian 11 (codename: Bullseye). DHCP on on by default so you may want to check your network router to get back the IP address assigned to your Keysas at boot.</address>
<p>To protected the <b>Keysas</b> against various attacks like BadUSB, only mass storage device like USB keys or disks are discovered by your <b>Keysas</b> station.
To sign a new output device, you will have to connect using <b>SSH</b> to you <b>Keysas</b> station:</p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">ssh keysas-sign@192.168.XX.YY (IP retrived via DHCP)</span>
</code></pre></div>
<div class="callout callout-warning">
Ths default password is Changeme. You will have to change it right after connecting with a strong and personnal password.
</div>
</section>
<section id="generation-des-cles-de-signature">
<h3>2 - Generating a keypair for signatures</h3>
<p>We are now going to create an asymetric keypair allowing us to sign and verify devices for output:</p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">sudo /usr/bin/keysas-sign --generate=true --password=Toto007</span>
<span class="go">sudo chmod 600 /etc/keysas/keysas.priv</span>
<span class="go">sudo chattr +i /etc/keysas/keysas.priv</span>
</code></pre></div>
<div class="callout callout-warning">
Do not forget to change the password used in the above commandline with yours :) 
</div>
<div class="callout callout-danger">
This keypair must be generated once while initializing your <b>Keysas</b> station. Changing this keypair 
may lead to verification failures on any devices previously signed. By default, the private and the public keys are stored under /etc/keysas.
It might be important to save your keypai in a safe place to be able to restore it if needed.
</div>
</section>
<section id="signature-d-un-peripherique-usb">
<h3>3 - Sign you USB device</h3>
<p>Once the keypair is generated, execute the following commandline:</p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">sudo /usr/bin/keysas-sign --watch=true</span>
</code></pre></div>
<p>Now plug the device you want to sign into you <b>Keysas</b> station. This device must be empty in order to avoid transfering unwanted files.</p>
<p>Press Crtl+c and copy/paste the commandline printed in your terminal and change the password with yours.
For example:</p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">sudo /usr/bin/keysas-sign -device=/dev/sda --sign=true --password=Toto007 --vendorid=0951 --modelid=160b --revision=1.00 --serial=Kingston_DataTraveler_2.0_0019E000B4625C8B0A070016-0:0</span>
</code></pre></div>
<p>The new USB device should be now successfully signed and formated using fat32 filesystem. You can of course reformat the device using any other filesystem supported by your <b>Keysas</b> station (ext2, ext3, ext4, fat32, exfat, ntfs).</p>
<div class="callout callout-info">
Please repeat this procedure with any devices when want to use for output.
</div>
<p>Once done, plug out and plug in your device to verify it is is know by the station as a output device.</p>
</section>
</section>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "AppWizard-en",
  props: [],
};
</script>

<style lang="sass">
@import "../assets/style/app.scss";
pre {
  background: $navy;
  color: $grey-light;
  padding: 5px;
  border-radius: 2px;
}
#no-signed-key {
  padding: 40px;
}
</style>
