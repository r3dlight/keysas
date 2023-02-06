<template>
  <div class="term">
    <span class="animate__animated animate__flash textterm">Not available yet !</span>
  </div>
</template>

<script>
import { getKeys, loadStore } from '../store/store.js'
import 'animate.css';

export default {
  name: 'AddYubikey',
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
.term {
  max-width: 1000px;
  margin: 40px auto;
  background: rgb(250, 250, 250);
  text-align: center;
  color: rgb(12, 12, 13);
  padding: 40px;
  border-radius: 5px;
  box-shadow: 5px 5px 5px black;
}

.textterm {
  color: rgb(1, 1, 1);
  text-align: center;
  font-weight: bold;
  font-size: 18px;
}
</style>
