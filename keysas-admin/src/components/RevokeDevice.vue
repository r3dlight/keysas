<template>
  <div class="box">
    <div class="container">
      <div class="row">
        <div class="col-sm">
          <div class="tip">
            <span class="text-info"><i class="bi bi-moon-stars-fill"> HELP</i></span>
            <br><br>
            <span class="tip-text">Click on the button and plug the USB key in your Keysas station within 30 seconds
              to revoke it</span><br>
          </div>
        </div>
        <div class="col-sm">
          <div class="tip">
            <button class="send btn btn-lg btn-outline-danger shadow" @click="onSubmitRevoke()"><i
                class="bi bi-check-square"> Revoke !</i></button>
          </div>
        </div>
      </div>
    </div>
    <div class="term">
      Revoking the output key:<br>
      <span v-if="revokeUsbStatus" class="animate__animated animate__flash textterm text-success">Success</span>
      <span v-else-if="revokeUsbStatus === false" class="animate__animated animate__flash textterm text-danger">Error:
        can't connect to the Keysas station !</span>
      <span v-else class="textterm spinner-border text-info"></span>
    </div>
  </div>

</template>

<script>
"use strict";

import 'animate.css';

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
    }
  },
  async mounted() {
    this.keys = await getKeys();

  },

  methods: {
    async displayKeysasList() {
      loadStore();
      this.keys = await getKeys();
    }
  }
}
</script>


<style lang="scss">

</style>
