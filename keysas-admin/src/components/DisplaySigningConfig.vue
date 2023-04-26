<template>
  <div class="tip">
    <h5 class="text-info"><i class="bi bi-moon-stars-fill"> HELP</i></h5>
    <br>
    <span class="tip-text">If you are configuring <b>Keysas-admin</b> for the first time, you need to create a
      <b>I</b>ncredible <b>K</b>eysas (Hybrid) <b>P</b>ost-<b>Q</b>uantum <b>P</b>ublic <b>K</b>ey <b>I</b>nfrastucture (IKPQPKI).
      Click on <b>Create a new IKPQPKI</b>.</span>
    <span class="tip-text"> Then, provide all the requested information to allow us to create a new IKPQPKI for you.<br> 
    When done, you will be able to start signing new outgoing USB devices and enrolling new Keysas stations.<br> 
    </span>
    <span class="tip-text">If you want to restore a IKPQPKI from another directory, choose <b>Load from local IKPQPKI</b></span>

  </div>
  <br>
  <div v-if="!hide" class="box-custom">
    <div class="text-center">
      <button class="send btn btn-light shadow" @click="hide = true; getPKIConfig()"><span class="bi bi-caret-up-fill"> Hide
        IKPQPKI configuration</span></button>
      <br><br>
      <div class="List">
        <ul class="list-group-item">
          <li class="list-group-item list-group-item-light">IKPQPKI directory: <span class="text-secondary">{{
            pkiPath
          }}</span></li>
          <li class="list-group-item list-group-item-light">Country: <span class="text-secondary">{{
            pkiConfig.country
          }}</span></li>
          <li class="list-group-item list-group-item-light">Organization name: <span class="text-secondary">{{
            pkiConfig.org_name
          }}</span></li>
          <li class="list-group-item list-group-item-light">Organization unit: <span class="text-secondary">{{
            pkiConfig.org_unit
          }}</span></li>
          <li class="list-group-item list-group-item-light">Validity: <span class="text-secondary">{{
            pkiConfig.validity
          }}</span></li>
        </ul>
      </div>
    </div>
  </div>
  <div v-else>
    <button class="send btn btn-light shadow" @click="hide = false; getPKIConfig()"><span class="bi bi-caret-down-fill">
        Show current PKI configuration</span></button>
  </div>
</template>

<script>
import { invoke } from "@tauri-apps/api";

export default {
  name: 'DisplaySigningConfig',
  computed: {
  },
  data() {
    return {
      rootKey: '',
      hide: true,
      pkiConfig: '',
      pkiPath: '',
    }
  },
  mounted() {
    //this.getSSHKeys();
  },

  methods: {
    async getPKIConfig() {
      //let paths = localStorage.getItem('rootCA');
      //console.log("Path: "+ paths);
      invoke('get_pki_config')
      .then((config) => {
        console.log(config);
        this.pkiConfig = config;
      })
      .catch((error) => console.error(error));
      invoke('get_pki_path')
      .then((dir) => {
        console.log(dir);
        this.pkiPath = dir;
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

.box-custom {
  max-width: 1000px;
  margin: 10px auto;
  background: white;
  color: white;
  text-align: left;
  padding: 10px;
  border-radius: 15px;
  font-size: 1.1em;
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
h3 {
  margin: 45px 0 0;
  color: #fff;
}
</style>
