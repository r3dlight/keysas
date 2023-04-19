<template>
    <div class="box">
      <div class="row">
        <div class="col-sm">
          <form class="add-form" @submit.prevent="onSubmitSign">
            <label type="text">Password:</label>
            <input type="password" required v-model="password" placeholder="8 caracters min" id="password" />
            <div v-if="passwordError" class="error"> {{ passwordError }}</div>
            <br>
            <div class="submit">
              <button @click="SignDevice()" class="send btn btn-outline-success shadow"><i class="bi bi-check-square"> Sign !</i></button>
              <br><br>
              <h3 v-if="show" class="validate animate__animated animate__zoomIn text-success">Done !</h3>
            </div>
          </form>
        </div>
        <div class="col-sm">
          <div class="tip">
            <span class="text-info"><i class="bi bi-moon-stars-fill"> Help</i></span>
            <br><br>
            <span class="tip-text">Enter your signing password and plug the new device within 30
              seconds to sign it.</span>
          </div>
        </div>
      </div>
      <div v-if="showSign" class="term">
        Please plug a new USB device... <br>
        <span v-if="signUsbStatus" class="animate__animated animate__flash textterm text-success">If the provided password
          is good, the new device should signed now !</span>
        <span v-else-if="shutdownStatus === false" class="animate__animated animate__flash textterm text-danger">Error:
          can't connect to the Keysas station or somthing went wrong !</span>
        <span v-else class="textterm spinner-border text-info"></span>
      </div>
    </div>

</template>

<script>
"use strict";

import { invoke } from "@tauri-apps/api";
import 'animate.css';

export default {
  name: 'SignKey',
  props: {
    signUsbStatus: Boolean,
  },
  computed: {

  },
  data() {
    return {
      password: '',
      keys: '',
      hide: false,
      showSign: false,
      passwordError: false,
    }
  },
  methods: {
    async SignDevice() {
      console.log('Calling sign_key');
      await invoke('sign_key', {
            password: this.password,
        })
        .then((res) => console.log("good"))
        .catch((error) => console.error(error));
    },
    async onSubmitSign(){
      this.showSign = true;
    }
  }
}
</script>


<style lang="scss">

</style>
