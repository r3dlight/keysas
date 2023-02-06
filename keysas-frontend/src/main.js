import 'bootstrap'
import { createApp } from 'vue'
import App from './App.vue'
import { createI18n } from "vue-i18n";

import en from './locales/en.json'
import fr from './locales/fr.json'

const i18n = createI18n({
    locale: 'fr',
    allowComposition: true, // you need to specify that!
    messages: {
      en,
      fr
    }
  })


const app = createApp(App);

app.use(i18n);

app.mount('#app')


