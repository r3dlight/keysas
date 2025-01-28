<template>
  <div class="tip">
    <h4 class="text-info"><i class="bi bi-moon-stars-fill"> HELP</i></h4>
    <br>
    <ul>
    <li class="tip-text">You must provide the application a dedicated SSH keypair to connect your Keysas
      stations.</li>
    <li class="tip-text">Only ED25519 in PEM format is supported.<br> To generate this new SSH keypair on your local
      machine, open a terminal and enter to following command:</li>
    </ul>
    <h4 class="text-center text-secondary"><b>ssh-keygen -m PEM -t ed25519 -f mykey</b></h4>
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
"use strict";

import { invoke } from "@tauri-apps/api/core";

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
    this.getSSHKeys();
  },

  methods: {
    /**
     * Fetch the path to the SSH keypair to display it
     */
    getSSHKeys() {
      invoke('get_sshkeys')
        .then((keys) => {
          this.pubKey = keys[0];
          this.privKey = keys[1];
          console.log("Path: " + this.pubKey);
          console.log("Path: " + this.privKey);
        })
        .catch((error) => console.error(error));
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
  max-width: 1200px;
  margin: 20px auto;
  background: white;
  text-align: left;
  padding: 1em;
  border-radius: 18px;
  color: white;
}

.tip-text {
  font-weight: normal;
  color: rgb(158, 161, 163);
  font-size: 1em;
}
</style>
