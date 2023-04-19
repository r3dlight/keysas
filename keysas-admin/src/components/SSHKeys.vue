<template>
  <form class="box" @submit.prevent="onSubmit">
    <label type="text"> Path to your SSH public key:</label>
    <input type="text" required v-model="publicKey" id="publicKey"/>
    <div class="text-center">
      <button class="btn btn-outline-secondary btn-sm shadow" @click="PublicKeyPath">Browse</button>
    </div>
    <div v-if="keysError" class="error"> {{ keysError }}
    </div>
      <br><br>
      <label type="text"> Path to your SSH private key: &nbsp;</label>
      <input type="text" required v-model="privateKey" id="private" />
      <div class="text-center">
    <button class="btn btn-outline-secondary btn-sm shadow" @click="PrivateKeyPath">Browse</button>
  </div>
  <div v-if="keysError" class="error"> {{ keysError }}</div>
  <br><br>
  <div class="submit">
    <button class="send btn btn-outline-success btn-lg shadow"><i class="bi bi-check-square"> Ok</i></button>
    <br><br>
    <h3 v-if="show" class="validate animate__animated animate__zoomIn text-success">Done !</h3>
  </div>
</form>
</template>

<script>
"use strict";

import { invoke } from "@tauri-apps/api";
import { getPublicKeyPath, getPrivateKeyPath} from "../utils/utils";


export default {
  name: 'SSHKeys',
  computed: {
    },
  data() {
    return {
      publicKey: '',
      privateKey: '',
      keysError: '',
      show: false,
    }
  },

  methods: {
    async PublicKeyPath(){
      this.publicKey = await getPublicKeyPath();
    },
    async PrivateKeyPath(){
      this.privateKey = await getPrivateKeyPath();
    },
    async onSubmit() {
      console.log('Form submitted');
      if (await invoke('save_sshkeys', {
            public: this.publicKey,
            private: this.privateKey,
      })) {
        this.ShowTwoSec();
        console.log("SSH keys saved");
      } else {
        console.log("Failed to save ssh keys");
      }
   },
    ShowTwoSec() {
      this.show=true;
      setTimeout(() => {
        this.show = false
        }, 2000)
      }  
    },
}
</script>

<style lang="scss">
h2 {
  font-weight: bold;
  color: #fff;
  font-size: 24px;
}
.validate {
  font-weight: bold;
  font-size: 24px;
}
label, p{
  color: rgb(132, 132, 132);
  display: inline-block;
  margin: 25px 0 15px;
  font-size: 1.1em;
  text-transform: uppercase;
  font-weight: bold;
}
form {
  max-width: 600px;
  margin: 30px auto;
  background: white;
  text-align: left;
  padding: 40px;
  border-radius: 10px;
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
button{
  border-radius: 20px;
}
.submit{
  text-align: center;
}
.error{
  color: #ff0062;
  margin-top: 10px;
  font-size: 0.8em;
  font-weight: bold;

}
</style>
