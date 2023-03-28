<template>
  <div class="term">
    Generating a new signing keypair: <br>
    <span v-if="CreateKeypairStatus" class="animate__animated animate__flash textterm text-success">New keypair
      successfully generated !</span>
    <span v-else-if="CreateKeypairStatus === false" class="animate__animated animate__flash textterm text-danger">Error
      while generating the new keypair !</span>
    <span v-else class="textterm spinner-border text-info"></span>
  </div>
</template>

<script>
"use strict";

import 'animate.css';

export default {
  name: 'GenKeypair',
  props: {
    CreateKeypairStatus: Boolean,
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
