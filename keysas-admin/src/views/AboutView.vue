

<script>
import NavBar from '../components/NavBar.vue'

export default {
  name: 'AboutView',
  components: {
    NavBar
  },

  data() {
    return {
    }
  },
}

</script>

<template>
  <NavBar />
  <h2>Keysas-admin. Version 2.3</h2>
  <h2>Please visit <a href="#https://keysas.fr" class="website text-info">keysas.fr</a> to learn more </h2>
  <h3>Copyright. Keysas 2022-2024.</h3>
</template>

<style lang="scss">
h3 {
  font-weight: bold;
  color: #fff;
  font-size: 20px;
}

.website {
  font-weight: normal;
  font-size: 1em;
}
</style>
