<template>
  <NavBar />
  <div class="container">
    <div class="row">
      <h1>Add a new Keysas station !</h1>
    </div>
    <div class="row">
      <div class="col-sm">
        <AddStation />
      </div>
      <div class="col-sm">
        <DisplayKeysas />
      </div>
    </div>
  </div>
</template>

<script>
"use strict";

import NavBar from '../components/NavBar.vue'
import AddStation from '../components/AddStation.vue'
import DisplayKeysas from '../components/DisplayKeysas.vue'


export default {
  name: 'AddView',
  components: {
    NavBar,
    AddStation,
    DisplayKeysas
  },
  computed: {

  },
  data() {
    return {
      name: '',
      ip: ''
    }
  },

  methods: {
  }

}
</script>
