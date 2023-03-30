<template>
  <div class="tip">
    <h5 class="text-info"><i class="bi bi-moon-stars-fill"> Help</i></h5>
    <br>
    <span class="tip-text">You must provide the application a dedicated root 
      Certificate Authority keypair to setup the PKI.</span>
    <span class="tip-text"> ED25519 or ED448 keys are accepted in PKCS#12 format.<br> 
      To generate this new keypair on your local machine, open a terminal and 
      enter to following commands:</span>
    <br>
    <div class="terminal-left">
      <span class="textterminal"># Generate private key for the root CA</span><br>
      <span class="textterminal">> openssl genpkey -algorithm ed25519 -out root-priv.pem</span><br>
      <span class="textterminal"># Generate corresponding certificate</span><br>
      <span class="textterminal">> openssl req -new x509 -nodes -days 3650 -key root-priv.pem -out root-cert.pem</span><br>
      <span class="textterminal"># Generate PKCS#12 file with the two keys</span><br>
      <span class="textterminal">> openssl pkcs12 -export -out root-store.p12 -inkey root-priv.pem -in root-cert.pem</span><br>
      <span class="textterminal"># Clean private key file</span><br>
      <span class="textterminal">> rm ./root-priv.pem</span>
    </div>
  </div>
  <br>
  <div v-if="!hide" class="custom-li tip">
    <div class="text-center">
      <button class="send btn btn-light shadow" @click="hide = true; getRootKey()"><span class="bi bi-caret-up-fill"> Hide
          registred Root CA key</span></button>
      <br><br>
      <div class="List">
        <ul class="list-group-item">
          <li class="list-group-item list-group-item-light">Registred Root CA key:<br><span class="text-secondary">{{
            pubKey
          }}</span></li>
        </ul>
      </div>
    </div>
  </div>
  <div v-else>
    <button class="send btn btn-light shadow" @click="hide = false; getRootKey()"><span class="bi bi-caret-down-fill">
        Show registred Root CA key</span></button>
  </div>
</template>

<script>

export default {
  name: 'DisplaySigningConfig',
  computed: {
  },
  data() {
    return {
      rootKey: '',
      hide: true,
    }
  },
  mounted() {
    //this.getSSHKeys();
  },

  methods: {
    getRootKey() {
      let paths = localStorage.getItem('rootCA');
      //console.log("Path: "+ paths);
      this.rootKey = JSON.parse(paths).pub;
      console.log("Path: " + this.rootKey);
    }
  }
}
</script>


<style lang="scss">
label {
  color: rgb(132, 132, 132);
  display: inline-block;
  margin: 25px 0 15px;
  font-size: 1.1em;
  text-transform: uppercase;
  font-weight: bold;
}

.custom-li {
  max-width: 420px;
  margin: 30px auto;
  background: rgba(202, 235, 236, 0.123);
  text-align: center;
  padding: 40px;
  border-radius: 10px;
  font-size: 1em;
  font-weight: bold;
  box-shadow: 10px 5px 5px black;
}

input {
  display: block;
  padding: 10px 6px;
  width: 100%;
  box-sizing: border-box;
  border: none;
  border-bottom: 1px solid #ddd;
  color: #555;

}

button {
  border-radius: 20px;
}

.submit {
  text-align: center;
}

.error {
  color: #ff0062;
  margin-top: 10px;
  font-size: 0.8em;
  font-weight: bold;
}

.tip {
  max-width: 1000px;
  text-align: left;
  margin: 30px auto;
  background: white;
  padding: 40px;
  border-radius: 10px;
  box-shadow: 5px 5px 5px black;
  color: white;
  display: inline-block;
  font-size: 1.0em;
}

.tip-text {
  font-weight: normal;
  color: rgb(158, 161, 163);
  font-size: 1em;
}
</style>
