<template>
  <div class="term">
    Updating Keysas station: <br>
    <span v-if="updateStatus" class="animate__animated animate__flash textterm text-success">Keysas successfully
      updated.<br>Rebooting now !</span>
    <span v-else-if="updateStatus === false" class="animate__animated animate__flash textterm text-danger">Error while
      updating :'/</span>
    <span v-else class="textterm spinner-border text-info"></span>
  </div>
</template>

<script>
import { getKeys, loadStore } from '../store/store.js'
import 'animate.css';

export default {
  name: 'UpdateKeysas',
  props: {
    updateStatus: Boolean,
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
