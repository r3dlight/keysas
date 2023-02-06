<template>
    <!--<router-link to="/"><span class="bi bi-house-door-fill"> Home</span> </router-link>
    <router-link to="/add"><span class="bi bi-bag-plus"> Add a new Keysas</span></router-link>
    <router-link to="/manage"><span class="bi bi-diagram-3-fill"> Manage your Keysas</span></router-link>
    <router-link to="/config"><span class="bi bi-wrench-adjustable"> SSH configuration</span></router-link>
    <router-link to="/about"><span class="bi bi-sunglasses"> About</span></router-link>-->
    <router-view></router-view>
    <VueAwesomeSideBar
      v-model:miniMenu="min"
      v-model:collapsed="collapsed"
      :menu="Menu"
      vueRouterEnabel
      :dark="darkMode"
      :closeOnClickOutSide="false"
    ></VueAwesomeSideBar>
  
</template>

<script>
import "bootstrap/dist/css/bootstrap.min.css"
import "bootstrap"
import 'bootstrap-icons/font/bootstrap-icons.css'
import { dataDir } from "@tauri-apps/api/path"



export default {
  name: 'App',
  components: {
    //vueAwesomeSidebar
  },
  data: () => ({
    min: true,
    collapsed: false,
    darkMode: true,
    chace: null,
    screenWidth: 0,
    Menu: [
  {
    header: 'Keysas-admin'
  },
    {
    name: 'Home',
    icon: { text: 'home' , class: 'bi bi-house-door-fill' },
    href: '/'
  },
  {
    name: 'Version',
    icon: { text: 'about' , class: 'bi bi-sunglasses' },
    href: '/about'
  },
  {
    name: 'SSH configuration',
    icon: { text: 'config' , class: 'bi bi-wrench-adjustable' },
    href: '/config'
  },
  {
    header: 'Keysas stations'
  },
  {
    name: 'Add a new Keysas station',
    icon: { text: 'add' , class: 'bi bi-plus-circle' },
    href: '/add'
  },
  {
    name: 'Manage registred stations',
    icon: { text: 'manage' , class: 'bi bi-diagram-3-fill' },
    href: '/manage'
  },
],
  })
}
</script>

<style lang="scss">
#app {
  font-family: Avenir, Arial, Helvetica, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  //margin-top: 20px;

}
body {
  margin: 0;
  background-image: linear-gradient(to right, #7a7979 0%, rgb(41, 40, 40) 100%);
}

nav {
  //padding: 10px;
a {
    //font-weight: bold;
    font-style: normal;
    color: #fafafa;
    margin-left: 1%;

&.router-link-exact-active {
      color: #ffffff;
      margin-left: 1%;
    }
  }
//h2 {
//  font-weight: bold;
//  color: #fff;
//  font-size: 24px;
//  }
}
</style>
