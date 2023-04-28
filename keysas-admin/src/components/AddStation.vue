<template>
  <form class="add-form" @submit.prevent="onSubmit">
    <p> Name of the new Keysas station:</p>
    <input required v-model="name" />
    <div v-if="nameError" class="error"> {{ nameError }}</div>
    <br />
    <br />
    <p> IP of the new Keysas station:</p>
    <input required v-model="ip" />
    <div v-if="ipError" class="error"> {{ ipError }}</div>
    <br><br>
    <div class="submit">
      <button class="send btn btn-outline-success btn-lg shadow"><i class="bi bi-check-square"> Add</i></button>
      <br><br>
      <h3 v-if="show" class="validate animate__animated animate__zoomIn text-success">Done !</h3>
    </div>
  </form>
</template>

<script>
"use strict";

import { invoke } from "@tauri-apps/api";

export default {
  name: 'AddStation',
  props: {
    //message: String,
  },
  computed: {
  },
  data() {
    return {
      name: '',
      ip: '',
      nameError: '',
      ipError: '',
      show: false,
    }
  },

  methods: {
    async onSubmit() {
      console.log('Form submitted');
      this.nameError = this.name.length > 4 ?
        '' : "Name must be at least 5 chars long"
      let ipv4_regex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/gm;
      this.ipError = ipv4_regex.test(this.ip) ?
        '' : "Invalid IP format"
      if (!this.nameError && !this.ipError) {
        console.log('setData called');
        await invoke('save_station', {
            name: this.name,
            ip: this.ip,
        });
        console.log("Device added:", this.name, this.ip);
        this.ShowTwoSec();
      }
      else {
        console.log('setData Not called')
      }
    },
    ShowTwoSec() {
      this.show = true;
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

label,
p {
  color: rgb(132, 132, 132);
  display: inline-block;
  margin: 25px 0 15px;
  font-size: 1.1em;
  text-transform: uppercase;
  font-weight: bold;
}

form {
  max-width: 8000px;
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

.tip-text {
  font-weight: normal;
  color: rgb(158, 161, 163);
  font-size: 1em;
}
</style>
