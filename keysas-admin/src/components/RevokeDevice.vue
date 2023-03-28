<template>
  <div class="term">
    Revoking the output key:<br>
    <span v-if="revokeUsbStatus" class="animate__animated animate__flash textterm text-success">Success</span>
    <span v-else-if="revokeUsbStatus === false" class="animate__animated animate__flash textterm text-danger">Error:
      can't connect to the Keysas station !</span>
    <span v-else class="textterm spinner-border text-info"></span>
  </div>
</template>

<script>
"use strict";

import 'animate.css';

export default {
  name: 'RevokeKeypair',
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
