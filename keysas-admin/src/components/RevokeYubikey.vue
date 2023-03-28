<template>
  <div class="term">
    <span class="animate__animated animate__flash textterm">Not available yet !</span>
  </div>
</template>

<script>
"use strict";

import 'animate.css';

export default {
  name: 'RevokeYubikey',
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
