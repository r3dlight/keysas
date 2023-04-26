<template>
  <div class="tip">
    <h5 class="text-info"><i class="bi bi-moon-stars-fill"> HELP</i></h5>
    <br>
    <span class="tip-text">Add here the Keysas stations you want to manage with this application.</span><br>
    <span class="tip-text">You can find the IP address in the Help menu of your Keysas station <i
        class="bi bi-emoji-wink"></i></span>
  </div>
  <br>
  <div v-if="!hide" class="custom-li tip">
    <div class="text-center">
      <button class="send btn btn-light shadow" @click="hide = true; displayKeysasList()"><span
          class="bi bi-caret-up-fill"> Hide registred Keysas stations</span></button>
      <br><br>
    </div>
    <div class="List">
      <ul class="list-group-item">
        <li class="list-group-item list-group-item-light" v-for="(device, key) in stations" :key="key">
          {{ device.name }}: {{ device.ip }}
          <br />
        </li>
      </ul>
    </div>
  </div>
  <div v-else>
    <button class="send btn btn-light shadow" @click="hide = false"><span class="bi bi-caret-down-fill"> Show registred
        Keysas stations</span></button>
  </div>
</template>

<script>
"use strict";

import { invoke } from "@tauri-apps/api";

export default {
  name: 'DisplayKeysas',
  computed: {

  },
  data() {
    return {
      stations: '',
      hide: true,
    }
  },
  async mounted() {
    invoke('list_stations')
      .then((list) => this.stations = JSON.parse(list))
      .catch((error) => console.error(error));
  },

  methods: {
    async displayKeysasList() {
      invoke('list_stations')
        .then((list) => this.stations = list)
        .catch((error) => console.error(error));
    }
  },
    async getKeysasIP(keysas) {
      invoke('get_station_ip', {name: keysas})
        .then((ip) => {return ip;})
        .catch((error) => console.log(error));
    },
}
</script>


<style lang="scss">
label,
p {
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
  background: rgb(255, 255, 255);
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
</style>
