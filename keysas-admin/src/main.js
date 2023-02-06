import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import vueAwesomeSidebar from 'vue-awesome-sidebar'
import 'vue-awesome-sidebar/dist/vue-awesome-sidebar.css'

createApp(App)
    .use(router)
    .use(vueAwesomeSidebar)
    .mount('#app')
