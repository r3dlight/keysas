<template>
  <NavBar />
  <div class="container">
    <div class="row">
      <h2>Administration console configuration</h2>
      <br>
    </div>
    <div class="row">
      <h3>SSH configuration</h3>
      <div class="col-sm">
        <SSHKeys />
      </div>
      <div class="col-sm">
        <DisplaySSHConfig />
      </div>
    </div>
    <div class="row">
      <h3>PKI configuration</h3>
      <div class="col-sm">
        <SigningKeys />
      </div>
      <div class="col-sm">
        <DisplaySigningConfig />
      </div>
    </div>
  </div>
</template>

<script>
import NavBar from '../components/NavBar.vue'
import SSHKeys from '../components/SSHKeys.vue'
import DisplaySSHConfig from '../components/DisplaySSHConfig.vue'
import SigningKeys from '../components/SigningKeys.vue'
import DisplaySigningConfig from '../components/DisplaySigningConfig.vue'


export default {
  name: 'AddView',
  components: {
    NavBar,
    SSHKeys,
    DisplaySSHConfig,
    SigningKeys,
    DisplaySigningConfig
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
