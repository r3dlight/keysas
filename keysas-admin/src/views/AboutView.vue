

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
  <h2>Version 2.2</h2>
  <h2>Please visit <a href="#https://keysas.fr" class="text-primary">keysas.fr</a> to learn more </h2>
  <h3>Copyright Keysas 2022-2023.</h3>
</template>

<style lang="scss">
h3 {
  font-weight: bold;
  color: #fff;
  font-size: 20px;
}
</style>
