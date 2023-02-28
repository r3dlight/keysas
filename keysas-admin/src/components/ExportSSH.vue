<template>
  <div class="term">
    Exporting SSH public key to Keysas station:<br>
    <span v-if="exportSSHStatus" class="animate__animated animate__flash textterm text-success">Export successfully done
      !<br>You should change the default password for user keysas now.</span>
    <span v-else-if="exportSSHStatus === false" class="animate__animated animate__flash textterm text-danger">Error:
      cannot connect to the Keysas station !</span>
    <span v-else class="spinner-border text-info"></span>
  </div>
</template>

<script>
import 'animate.css';

export default {
  name: 'ExportSSH',
  props: {
    exportSSHStatus: Boolean,
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
