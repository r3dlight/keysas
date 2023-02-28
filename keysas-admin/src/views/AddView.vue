<template>
  <NavBar />
  <div class="container">
    <div class="row">
      <h2>Add a new Keysas station !</h2>
    </div>
    <div class="row">
      <div class="col-sm">
        <AddForm />
      </div>
      <div class="col-sm">
        <DisplayKeysas />
      </div>
    </div>
  </div>
</template>

<script>
import NavBar from '../components/NavBar.vue'
import AddForm from '../components/AddForm.vue'
import DisplayKeysas from '../components/DisplayKeysas.vue'


export default {
  name: 'AddView',
  components: {
    NavBar,
    AddForm,
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
