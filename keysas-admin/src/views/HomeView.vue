<template>
  <NavBar />
  <div class="box">
    <p>Welcome to Keysas-admin ! <br> This application allows you to manage your Keysas stations.<br>
      You can register news Keysas stations, update them, sign USB devices and much more.
    </p><br /><br />
    <h1 class="text-info fw-bold bi bi-magic"> QUICK START</h1>
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
        <li class="doc">Then, <b>set the path</b> of both keys in the <b>"Admin configuration/SSH configuration"</b> menu ;</li>
      </ul>
      <br>
      <li><b>Generate a IKPQPKI</b></li>
      <ul>
        <li>To be able to sign your outgoing USB devices and to enroll new Keysas stations, you need to create a <b>IKPQPKI</b> 
          <br>(<b>I</b>ncredible <b>K</b>eysas (Hybrid) <b>P</b>ost-<b>Q</b>uantum <b>P</b>ublic <b>K</b>ey <b>I</b>nfrastucture) &#x1F601;</li>
        <li>If you have never created a IKPQPKI, go to "<b>Admin configuration</b>-><b>IKPQPKI configuration</b>" and click on "<b>Create a new IKPQPKI</b>"</li>
        <li>Provide the information requested to build your own custom PKI</li>
        <li>Be patient, this may take a while &#x2615;</li>
      </ul>
      <br>
      <li><b>Enroll you Keysas stations</b></li>
      <ul>
        <li>You can now start <b>adding</b> new keysas stations in the <b>"Add a new Keysas"</b> menu
          providing a name and an IP address</li>
        <li>When done, <b>export</b> the public key by clicking the <b>"Export SSH pubkey"</b> button for each station added</li>
      </ul>
      <br>
      <li><b>Sign your outgoing USB keys</b></li>
      <ul>
        <li>You can now start signing at least one USB device in "<b>Admin configuration</b>-><b>USB Signing</b>"</li>
        <li>Type the password provided during your IKPQPKI creation and plug the USB key</li>
        <li>Be patient, this may take a while &#x2615;</li>
      </ul>
      <br>
      <li><b>You're now ready to go !</b></li>
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
