import Vue from 'vue'
import Router from 'vue-router'
import Pagenotfound from '@/components/Pagenotfound'
import Main from '@/components/Main'
import Help from '@/components/Help'
import Signin from '@/components/User/Signin'
import Signup from '@/components/User/Signup'
import Profile from '@/components/User/Profile'
import Testseries from '@/components/Testseries'
import store from './store'

Vue.use(Router)

const router = new Router({
  //mode: 'history',
  //base: '/',
  routes: [
	 {
      path: '*',
      component: Pagenotfound
    },
	{
      path: '/',
	  redirect: '/fooldal'
    },
	{
      path: '/fooldal',
      name: 'Main',
      component: Main,
	  meta: { requiresAuth: false }
    },
	{
      path: '/sugo',
      name: 'Help',
      component: Help,
	  meta: { requiresAuth: false }
    },
    {
      path: '/bejelentkezes',
      name: 'Signin',
      component: Signin,
	  meta: { requiresAuth: false }
    },
	{
      path: '/regisztracio',
      name: 'Signup',
      component: Signup,
	  meta: { requiresAuth: false }
    },
	{
      path: '/profil',
      name: 'Profile',
      component: Profile,
	  meta: { requiresAuth: true }
    },
	{
      path: '/tesztsorozat',
      name: 'Testseries',
      component: Testseries,
	  meta: { requiresAuth: true }
    }
  ]
})

router.beforeEach((to, from, next) => {
	if(to.meta.requiresAuth){
		if(store.getters.user!== null && store.getters.user!== undefined){
			next()
		} else {
			next('/bejelentkezes')
		}
	}
	next()
})

export default router