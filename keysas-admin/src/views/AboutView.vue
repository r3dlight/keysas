

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

  methods: {

  }
}

</script>

<template>
  <NavBar />
  <h2>Version 0.1.2</h2>
  <h3>Copyright Keysas 2022-2023.</h3>
</template>

<style lang="scss">
h3 {
  font-weight: bold;
  color: #fff;
  font-size: 20px;
}
</style>
