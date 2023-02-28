<template>
  <div class="tip">
    <h5 class="text-info"><i class="bi bi-moon-stars-fill"> Help</i></h5>
    <br>
    <span class="tip-text">You must provide the application a dedicated SSH keypair to connect your Keysas
      stations.</span>
    <span class="tip-text">Only ED25519 in PEM format is supported.<br> To generate this new SSH keypair on your local
      machine, open a terminal and enter to following command:</span>
    <br>
    <span class="tip-text"><b>ssh-keygen -m PEM -t ed25519 -f mykey</b></span>
  </div>
  <br>
  <div v-if="!hide" class="custom-li tip">
    <div class="text-center">
      <button class="send btn btn-light shadow" @click="hide = true; getSSHKeys()"><span class="bi bi-caret-up-fill"> Hide
          registred SSH keys</span></button>
      <br><br>
      <div class="List">
        <ul class="list-group-item">
          <li class="list-group-item list-group-item-light">Registred public key:<br><span class="text-secondary">{{
            pubKey
          }}</span></li>
          <li class="list-group-item list-group-item-light">Registred private key:<br><span class="text-secondary">{{
            privKey
          }}</span></li>
        </ul>
      </div>
    </div>
  </div>
  <div v-else>
    <button class="send btn btn-light shadow" @click="hide = false; getSSHKeys()"><span class="bi bi-caret-down-fill">
        Show registred SSH keys</span></button>
  </div>
</template>

<script>

export default {
  name: 'DisplaySSHConfig',
  computed: {
  },
  data() {
    return {
      pubKey: '',
      privKey: '',
      hide: true,
    }
  },
  mounted() {
    //this.getSSHKeys();
  },

  methods: {
    getSSHKeys() {
      let paths = localStorage.getItem('ssh');
      //console.log("Path: "+ paths);
      this.pubKey = JSON.parse(paths).pub;
      this.privKey = JSON.parse(paths).priv;
      console.log("Path: " + this.pubKey);
      console.log("Path: " + this.privKey);
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
