import Vue from 'vue'
import './plugins/vuetify'
import 'vuetify/dist/vuetify.min.css' // Ensure you are using css-loader
import App from './App.vue'
import router from './router'
import store from './store'
import axios from 'axios'
import AlertCmp from './components/Shared/Alert.vue'

Vue.config.productionTip = false
Vue.component('app-alert', AlertCmp)

new Vue({
  router,
  store,
  render: h => h(App),
  created () {
	  //this.$store.dispatch('autoSignIn', null)
  }
}).$mount('#app')