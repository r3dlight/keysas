<template>
  <div class="box">
    <div class="container">
      <div class="row">
        <div class="col-sm">
          <div class="tip">
            <h4 class="text-info"><i class="bi bi-moon-stars-fill"> HELP</i></h4>
            <br>
            <span class="tip-text">Click on the button and plug the USB key in your Keysas station within 30 seconds
              to revoke it</span>
            <br>
            <br>
            <div class="text-center">
            <button class="send btn btn-lg btn-danger shadow" @click="onSubmitRevoke()"><i
                class="bi bi-check-square"> Revoke !</i>
            </button>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div v-if="revokeUsbStatus" class="term">
      Revoking the USB device:<br>
      <span v-if="revokeUsbStatus === true" class="animate__animated animate__flash textterm text-success">Success</span>
      <span v-else-if="revokeUsbStatus === false" class="animate__animated animate__flash textterm text-danger">Error:
        can't revoke the device !</span>
      <span v-else-if="revokeUsbStatus == 'waiting'" class="textterm spinner-border text-info"></span>
    </div>
  </div>

</template>

<script>
"use strict";

import 'animate.css';
import { invoke } from "@tauri-apps/api/core";

export default {
  name: 'RevokeDevice',
  props: {
    revokeUsbStatus: Boolean,
  },
  computed: {
  },
  data() {
    return {
      keys: '',
      hide: false,
      revokeUsbStatus: undefined
    }
  },
  async mounted() {
  },

  methods: {
    async onSubmitRevoke() {
      this.revokeUsbStatus = "waiting";
      await invoke('revoke_usb')
        .then((res) => this.revokeUsbStatus = res)
        .catch((error) => console.error(error));
    },
  },
}
</script>


<style lang="scss">
  
.tip-text {
  font-weight: normal;
  color: rgb(101, 101, 101);
  font-size: 1.2em;
}

</style>
