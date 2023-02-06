<template>
  <NavBar />
  <div class="container">
    <div class="row">
      <h2>Add or change your SSH configuration</h2>
      <br>
    </div>
    <div class="row">
      <div class="col-sm">
        <SSHKeys />
      </div>
      <div class="col-sm">
        <DisplaySSHConfig />
      </div>
    </div>
  </div>
</template>

<script>
import NavBar from '../components/NavBar.vue'
import SSHKeys from '../components/SSHKeys.vue'
import DisplaySSHConfig from '../components/DisplaySSHConfig.vue'


export default {
  name: 'AddView',
  components: {
    NavBar,
    SSHKeys,
    DisplaySSHConfig,
  },
  computed: {
  },
  data() {
    return {
    }
  },

  methods: {
  }

}
</script>
