<template>
    <div class="box">
      <div class="row">
        <div class="col-sm">
          <form class="add-form" @submit.prevent="onSubmitSign">
            <label type="text">IKPQPKI Password:</label>
            <input type="password" required v-model="password" placeholder="8 caracters min" id="password" />
            <div v-if="passwordError" class="error"> {{ passwordError }}</div>
            <br>
            <div class="submit">
              <button @click="SignDevice()" class="send btn btn-lg btn-success shadow"><i class="bi bi-check-square"> Sign !</i></button>
              <br><br>
              <h3 v-if="show" class="validate animate__animated animate__zoomIn text-success">Done !</h3>
            </div>
          </form>
        </div>
        <div class="col-sm">
          <div class="tip">
            <h4 class="text-info"><i class="bi bi-moon-stars-fill"> HELP</i></h4>
            <span class="tip-text">Enter your signing password and plug the new device within 30
              seconds to sign it. Before signing your first device:</span>
              <li class="tip-text"><b>On GNU/Linux:</b></li>
              <ul>
                <li class="tip-text">Create a new file <b>/etc/udev/rules.d/71-keysas.rules</b></li>
                <li class="tip-text">Copy and paste this in the new file: <br><b class="text-secondary">SUBSYSTEMS=="usb", MODE="0660", TAG+="uaccess",ENV{ID_VENDOR_ID}="$attr{vendor}",ENV{ID_MODEL_ID}="$attr{model}"</b></li>
                <li class="tip-text">Open a terminal and execute this: <br> <b class="text-secondary">udevadm trigger && udevadm control --reload</b></li>
              </ul>
          </div>
        </div>
      </div>
      <div v-if="showSign" class="term">
        <span v-if="signUsbStatus" class="animate__animated animate__flash textterm text-success">
          Success, the new device should signed now !</span>
        <span v-else-if="signUsbStatus === false" class="animate__animated animate__flash textterm text-danger">
          Error while signing the new device !</span>
        <div v-else> 
          Please plug a new USB device and wait<br> 
          <span class="textterm spinner-border text-info"></span>
        </div>
      </div>
    </div>

</template>

<script>
"use strict";

import { invoke } from "@tauri-apps/api/core";
import 'animate.css';

export default {
  name: 'SignDevice',
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
      signUsbStatus: undefined,
    }
  },
  methods: {
    async SignDevice() {
      console.log('Calling sign_key');
      await invoke('sign_key', {
            password: this.password,
        })
        .then((res) => this.signUsbStatus = res)
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
