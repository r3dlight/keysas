<template>
  <NavBar />
  <div class="box">
    <p>Welcome to Keysas-admin ! <br> This application allows you to manage your Keysas stations.<br>
      You can register news Keysas stations, update them, sign USB devices and much more.
    </p><br /><br />
    <span class="text-info fw-bold bi bi-magic"> QUICK START</span>
    <br />
    <ul class="doc">
      <li><b>SSH configuration</b></li>
      <ul>
        <li>First, start by <b>creating</b> a ED25519 <b>private key</b> and the associated <b>public key</b> on your
          computer ;<br />
          This keypair should only be <b>dedicated</b> to the administration of your Keysas stations.
          To do so, open a <b>terminal</b> and use the following command:</li>
        <div class="terminal-left">
          <span class="textterminal">> ssh-keygen -m PEM -t ed25519 -f mykey</span>
        </div>
        <br>
        <li class="doc">Then, <b>set the path</b> of both keys in the <b>"SSH configuration"</b> menu ;</li>
      </ul>
      <li><b>Generate key to sign USB devices</b></li>
      <ul>
        <li>Create a ED25519 key pair and generate the corresponding self-sign certificate. This key pair must then be wrapped in a PKCS#12 file. This can be done with the following commands:</li>
        <div class="terminal-left">
          <span class="textterminal"># Generate private key for USB device signing</span><br>
          <span class="textterminal">> openssl genpkey -algorithm ed25519 -out admin-priv-usb.pem</span><br>
          <span class="textterminal"># Generate corresponding certificate</span><br>
          <span class="textterminal">> openssl req -new x509 -nodes -days 3650 -key admin-priv-usb.pem -out admin-usb-cert.pem</span><br>
          <span class="textterminal"># Generate PKCS#12 file with the two keys</span><br>
          <span class="textterminal">> openssl pkcs12 -export -out admin-usb-store.p12 -inkey admin-priv-usb.pem -in admin-usb-cert.pem</span><br>
          <span class="textterminal"># Clean private key file</span><br>
          <span class="textterminal">> rm ./admin-priv-usb.pem</span>
        </div>
      </ul>
      <li><b>Generate key to sign Keysas stations</b></li>
      <ul>
        <li>Create a ED25519 key pair and generate the corresponding self-sign certificate. This key pair must then be wrapped in a PKCS#12 file. This can be done with the following commands:</li>
        <div class="terminal-left">
          <span class="textterminal"># Generate private key for keysas stations signing</span><br>
          <span class="textterminal">> openssl genpkey -algorithm ed25519 -out admin-priv-st.pem</span><br>
          <span class="textterminal"># Generate corresponding certificate</span><br>
          <span class="textterminal">> openssl req -new x509 -nodes -days 3650 -key admin-priv-st.pem -out admin-st-cert.pem</span><br>
          <span class="textterminal"># Generate PKCS#12 file with the two keys</span><br>
          <span class="textterminal">> openssl pkcs12 -export -out admin-st-store.p12 -inkey admin-priv-st.pem -in admin-st-cert.pem</span><br>
          <span class="textterminal"># Clean private key file</span><br>
          <span class="textterminal">> rm ./admin-priv-st.pem</span>
        </div>
      </ul>
      <li>You can now <b>add</b> a new device in the <b>"Add a new Keysas"</b> menu
        providing a name and an IP address ;</li>
      <li>When done, <b>export</b> the public key by clicking the <b>"Export SSH pubkey"</b> button ;</li>
      <li>You can now change the default keysas user's password ;</li>
      <li>You're now ready to go !</li>
    </ul>
    <br><br><span class="website">Please visit <a href="#https://keysas.fr" class="text-primary">keysas.fr</a> to learn
      more !</span>
  </div>
</template>

<script>
// @ is an alias to /src
import NavBar from '../components/NavBar.vue'

export default {
  name: 'HomeView',
  components: {
    NavBar
  }
}
</script>

<style>
.box {
  max-width: 1000px;
  margin: 40px auto;
  background: white;
  text-align: center;
  padding: 40px;
  border-radius: 15px;
}

span {
  font-weight: normal;
  font-size: 1em;
}

.website {
  font-weight: normal;
  font-size: 1em;
  color: rgb(132, 132, 132);
}

ul.doc {
  color: rgb(132, 132, 132);
  text-align: left;
  display: inline-block;
  margin: 25px 0 15px;
  font-size: 1.1em;
}

h2 {
  color: white;
}

.terminal-left {
  max-width: 1800px;
  margin: 10px auto;
  background: rgb(0, 0, 0);
  text-align: left;
  color: rgb(12, 12, 13);
  padding: 20px;
  border-radius: 5px;
  box-shadow: 5px 5px 5px black;
}

.textterminal {
  color: rgb(245, 242, 242);
  font-weight: bold;
  font-size: 18px;
}

p {
  color: rgb(132, 132, 132);
  display: inline-block;
  margin: 25px 0 15px;
  font-size: 1.1em;
  text-transform: uppercase;
  font-weight: bold;
}
</style>
