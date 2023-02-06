<template>
  <div class="term">
    Rebooting Keysas station: <br>
    <span v-if="rebootStatus" class="animate__animated animate__flash textterm text-success">Success</span>
    <span v-else-if="rebootStatus === false" class="animate__animated animate__flash textterm text-danger">Error: can't
      connect to the Keysas station !</span>
    <span v-else class="textterm spinner-border text-info"></span>
  </div>
</template>

<script>
import 'animate.css';

export default {
  name: 'RebootKeysas',
  props: {
    rebootStatus: Boolean,
  },
  computed: {
  },
  data() {
    return {
    }
  },
  async mounted() {

  },

  methods: {

  }
}
</script>


<style lang="scss">

</style>
