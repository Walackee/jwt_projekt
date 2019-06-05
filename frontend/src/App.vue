
<template>
	<div id="app">
  <v-app id="inspire">
    <v-navigation-drawer
      :clipped="drawer.clipped"
      :fixed="drawer.fixed"
      :permanent="drawer.permanent"
      :mini-variant="drawer.mini"
      v-model="drawer.open"
      app
    >
      <v-list>
	   <v-toolbar flat class="transparent">
        <v-list class="pa-0">
          <v-list-tile avatar @click="toggleMiniDrawer">
            <v-list-tile-avatar>
               <v-list-tile-action><i class="material-icons">arrow_right_alt</i></v-list-tile-action>
            </v-list-tile-avatar>
            <v-list-tile-content>
              <v-list-tile-title>Oldalsáv</v-list-tile-title>
            </v-list-tile-content>
          </v-list-tile>
        </v-list>
      </v-toolbar>
		<v-divider></v-divider>
		
		<v-list-tile to="/">
          <v-list-tile-action><i class="material-icons">home</i></v-list-tile-action>
          <v-list-tile-content><v-list-tile-title>Főoldal</v-list-tile-title>
          </v-list-tile-content>
        </v-list-tile>
		
        <v-list-tile to="/sugo">
          <v-list-tile-action><i class="material-icons">help</i></v-list-tile-action>
          <v-list-tile-content><v-list-tile-title>Súgó</v-list-tile-title>
          </v-list-tile-content>
        </v-list-tile>
      </v-list>
	  <v-list class="pt-0" dense>
	   <v-list-tile v-for="item in menuItems" :key="item.title" :to="item.link">
	    <v-list-tile-action>
		 <v-icon>{{ item.icon }}</v-icon>
        </v-list-tile-action>
        <v-list-tile-content>
		 <v-list-tile-title>{{ item.title }}</v-list-tile-title>
        </v-list-tile-content>
       </v-list-tile>
       <v-list-tile
          v-if="userIsAuthenticated"
          @click="onLogout">
          <v-list-tile-action>
            <v-icon>exit_to_app</v-icon>
          </v-list-tile-action>
          <v-list-tile-content>Kijelentkezés</v-list-tile-content>
        </v-list-tile>
      </v-list>
	  
    </v-navigation-drawer>
    
    <v-toolbar app :fixed="toolbar.fixed" :clipped-left="toolbar.clippedLeft">
      <v-toolbar-side-icon 
        @click.stop="toggleDrawer"
      ></v-toolbar-side-icon>
      <v-toolbar-title>Tesztsorozat</v-toolbar-title>
	  <v-spacer></v-spacer>
	  <v-toolbar-title>{{bejelentkezvemint}}</v-toolbar-title>
    </v-toolbar>
	
    <v-content>
	  <main
		<router-view mb-3/>
	  </main>
    </v-content>
	<v-footer
    height="auto"
	>
    <v-layout
      justify-center
      row
      wrap
    >
      <v-btn
        v-for="(item, index) in links"
        :key="index"
        flat
        round
		:href="item.link"
		target="_blank"
      >
        {{ item.szoveg }}
      </v-btn>
      <v-flex
        py-3
        text-xs-center
        xs12
      >
        &copy; 2019 - Minden jog fenntartva - Szegedi Tudományegyetem.
      </v-flex>
    </v-layout>
  </v-footer>
  </v-app>
  </div>

</template>

<script>
import store from './store'
const port = 3004
const backend = `http://localhost:${port}`

document.title="Tesztsorozat"
export default {
  name: 'App',
  data () {
    return {
	   backend: backend,
	   links: [
		{szoveg: 'Tananyag', link: ''},
		{szoveg: 'Adatvédelmi irányelvek', link: ''},
		{szoveg: 'Szolgáltatás feltételei', link: ''}
      ],
	
	  drawer: {
      // sets the open status of the drawer
      open: true,
      // sets if the drawer is shown above (false) or below (true) the toolbar
      clipped: false,
      // sets if the drawer is CSS positioned as 'fixed'
      fixed: false,
      // sets if the drawer remains visible all the time (true) or not (false)
      permanent: true,
      // sets the drawer to the mini variant, showing only icons, of itself (true) 
      // or showing the full drawer (false)
      mini: true
    },
    toolbar: {
      //
      fixed: true,
      // sets if the toolbar contents is leaving space for drawer (false) or not (true)
      clippedLeft: false
    },
    footer: {
      // sets the CSS position of the footer
      fixed: true,
      // sets if the footer is full width (true) or gives space to the drawer (false)
      clippedLeft: true
    }
    }
  },
  computed: {
  
		bejelentkezvemint(){
			if(this.userIsAuthenticated){
				return this.$store.getters.useremail
			} else {
				return ""
			}
		},
	
      menuItems () {
        let menuItems = [
          {icon: 'lock_open', title: 'Bejelentkezés', link: '/bejelentkezes'},
		  {icon: 'face', title: 'Regisztráció', link: '/regisztracio'}
        ]
        if (this.userIsAuthenticated) {
          menuItems = [
			{icon: 'playlist_add_check', title: 'Tesztsorozat', link: '/tesztsorozat'},
            {icon: 'person', title: 'Profil', link: '/profil'}
          ]
        }
        return menuItems
      },
      userIsAuthenticated () {
        return this.$store.getters.user !== null && this.$store.getters.user !== undefined
      }
    },
	
	mounted() {
		this.$store.dispatch('ellenorzes')
	},
	
    methods: {
      onLogout () {
        this.$store.dispatch('logout')
      },
	      // changes the drawer to permanent
    makeDrawerPermanent () {
      this.drawer.permanent = true
      // set the clipped state of the drawer and toolbar
      this.drawer.clipped = false
      this.toolbar.clippedLeft = false
    },
    // toggles the drawer variant (mini/full)
    toggleMiniDrawer () {
      this.drawer.mini = !this.drawer.mini
    },
    // toggles the drawer type (permanent vs temporary) or shows/hides the drawer
    toggleDrawer () {
      if (this.drawer.permanent) {
        this.drawer.permanent = !this.drawer.permanent
        // set the clipped state of the drawer and toolbar
        this.drawer.clipped = true
        this.toolbar.clippedLeft = true
      } else {
        // normal drawer
        this.drawer.open = !this.drawer.open
      }
    }
    }
}
</script>