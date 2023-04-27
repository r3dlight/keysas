<template>
  <NavBar />
  <div class="container">
    <div class="row">
      <h1>Administration console configuration</h1>
      <br>
    </div>
  <div class="box">
    <button class="btn btn-outline-success btn-lg shadow" @click="flush(); ShowSign = !ShowSign;">
      <span class="bi bi-arrows-expand"> USB signing</span>
    </button>
    <button class="btn btn-outline-warning btn-lg shadow" @click="flush(); ShowRevoke = !ShowRevoke;">
      <span class="bi bi-arrows-expand"> USB revoking</span>
    </button>
    <button class="btn btn-outline-primary btn-lg shadow" @click="flush(); ShowSSH = !ShowSSH;">
      <span class="bi bi-arrows-expand"> SSH configuration</span>
    </button>
    <button class="btn btn-outline-danger btn-lg shadow" @click="flush(); ShowPKI = !ShowPKI;">
      <span class="bi bi-arrows-expand"> IKPQPKI configuration</span>
    </button>
  </div>
    <div class="row" v-if="ShowSign">
      <h3>USB device signing</h3>
      <div class="col-sm">
        <SignDevice />
      </div>
    </div>
    <div class="row" v-if="ShowRevoke">
      <h3>USB device revoking</h3>
      <div class="col-sm">
        <RevokeDevice />
      </div>
    </div>  
    <div class="row" v-if="ShowSSH">
      <h3>SSH configuration</h3>
      <div class="col-sm">
        <SSHKeys />
      </div>
      <div class="col-sm">
        <DisplaySSHConfig />
      </div>
    </div>
    <div class="row" v-if="ShowPKI">
      <h3>IKPQPKI configuration</h3>
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
import SignDevice from '../components/SignDevice.vue'
import RevokeDevice from '../components/RevokeDevice.vue'

export default {
  name: 'AdminView',
  components: {
    NavBar,
    SignDevice,
    SSHKeys,
    DisplaySSHConfig,
    SigningKeys,
    DisplaySigningConfig,
    RevokeDevice,
  },
  computed: {
  },
  data() {
    return {
      ShowSign: false,
      ShowRevoke: false,
      ShowSSH: false,
      ShowPKI: false,
    }
  },

  methods: {
    flush() {
      this.ShowSign = false;
      this.ShowRevoke = false;
      this.ShowSSH = false;
      this.ShowPKI = false;
    },
  }

}
</script>
