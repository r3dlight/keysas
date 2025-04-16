<template>
  <NavBar />
  <div class="box">
    <p class="intro">WELCOME ! <br> This application allows you to manage your Keysas stations.<br /> You can register news Keysas stations, update them, sign USB devices and much more.
    </p>
    <br />
    <h1 class="text-info fw-bold bi bi-magic"> QUICK START</h1>
    <ul class="doc">
      <li><b class="text-info text-bold "> SSH CONFIGURATION</b></li>
      <ul>
        <li>First, start by <b>creating</b> a ED25519 <b>private key</b> and the associated <b>public key</b> on this
          computer<br />
          This keypair should only be <b>dedicated</b> to the administration of your Keysas stations.
          To do so, open a <b>terminal</b> and use the following command:</li>
        <div class="terminal-left">
          <span class="textterminal">ssh-keygen -m PEM -t ed25519 -f mykey</span>
        </div>
        <br>
        <li class="doc">You may, of course, change <b>mykey</b> with the name of your choice</li>
        <li class="doc">Then, <b>set the path</b> of both keys in the <b>"Admin configuration -> SSH configuration"</b> menu</li>
      </ul>
      <br>
      <li><b class="text-info text-bold">GENERATE A IKPQPKI</b></li>
      <ul>
        <li>To be able to <b>sign</b> your output USB devices and to <b>enroll</b> new Keysas stations, you need to create a <b>IKPQPKI</b> 
          <br>(<b>I</b>ncredible <b>K</b>eysas (Hybrid) <b>P</b>ost-<b>Q</b>uantum <b>P</b>ublic <b>K</b>ey <b>I</b>nfrastucture) &#x1F601;</li>
        <li>If you have never created a IKPQPKI, go to "<b>Admin configuration -> IKPQPKI configuration</b>" and click on "<b>Create a new IKPQPKI</b>"</li>
        <li><b>Provide the information</b> requested to build your own custom PKI</li>
        <li><b>Be patient</b>, this may take a while <b>&#x2615;</b></li>
      </ul>
      <br>
      <li><b class="text-info text-bold">ENROLL YOUR KEYSAS STATIONS</b></li>
      <ul>
        <li>You can now start <b>adding</b> new keysas stations in the <b>"Add a new Keysas"</b> menu
          providing a name and an IP address</li>
        <li>When done, go to the <b>"Manage registred stations"</b> menu and <b>export</b> the public SSH key by clicking the <b>"Export SSH pubkey"</b> button for <b>each station</b> added</li>
        <li>Then, click on <b>more</b>, and clienk on <b>Enroll</b>, provide your IKPQPKI password then click on <b>"Enroll it"</b></li>
        <li><b>Be patient</b>, this may take some time <b>&#x2615;</b></li>
      </ul>
      <br>
      <li><b class="text-info text-bold">SIGN YOUR OUTPUT USB keys</b></li>
      <ul>
        <li>You can now start <b>signing</b> at least one USB device in "<b>Admin configuration -> USB Signing</b>"</li>
        <li>Type the password provided during your IKPQPKI creation and plug the USB key</li>
        <li>One again, <b>be patient</b>, this may take a while <b>!</b></li>
      </ul>
      <br>
      <li><b class="text-info">THAT'S ALL, YOU ARE NOW READY TO GO !</b></li>
    </ul>
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
/* Conteneur principal */
.box {
  max-width: 1000px;
  /*margin: 15px 50px;*/
  margin: 15px 0 15px 12%; /* Ajoute 20px de marge uniquement à gauche */
  background-color: #fff;
  text-align: center;
  padding: 1em;
  border-radius: 18px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); /* Ombre légère pour moderniser */
}

/* Texte générique */
span {
  font-weight: normal;
  font-size: 0.9em; /* Légèrement réduit */
}

p, ul.doc {
  color: rgb(134, 134, 132);
  font-size: 1.2em; /* Taille réduite pour harmonisation */
  margin: 20px 0 15px; /* Marges ajustées pour l'équilibre visuel */
}

/* Style des listes */
ul.doc {
  text-align: left;
  display: inline-block;
}

/* Titres */
h2 {
  color: #fff;
  font-size: 1.6em; /* Réduction pour mieux correspondre à l'échelle globale */
}

/* Terminal */
.terminal-left {
  max-width: 1800px;
  margin: 10px auto;
  background-color: #000;
  text-align: left;
  color: #0c0c0d;
  padding: 20px;
  border-radius: 5px;
  box-shadow: 5px 5px 5px rgba(0, 0, 0, 0.5);
}

/* Texte dans le terminal */
.textterminal {
  color: #f5f2f2;
  font-weight: bold;
  font-size: 1em; /* Taille réduite pour un meilleur équilibre */
}

/* Texte spécifique */
p {
  font-weight: bold;
}

.welcome {
  font-size: 1.3em; /* Taille légèrement réduite */
  text-transform: uppercase;
  letter-spacing: 0.05em; /* Espacement subtil pour une meilleure lisibilité */
}

.intro {
  font-size: 1.1em; /* Harmonisation avec le reste du texte */
}
</style>

