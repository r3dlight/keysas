<template>
  <div class="term">
    Please plug a new USB key into the Keysas station... <br>
    <span v-if="signUsbStatus" class="animate__animated animate__flash textterm text-success">If the provided password
      is good, the new device should signed now !</span>
    <span v-else-if="shutdownStatus === false" class="animate__animated animate__flash textterm text-danger">Error:
      can't connect to the Keysas station or somthing went wrong !</span>
    <span v-else class="textterm spinner-border text-info"></span>
  </div>
</template>

<script>
"use strict";

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
