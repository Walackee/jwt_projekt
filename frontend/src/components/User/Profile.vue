<template>
  <v-container>
    <v-layout row class="mb-2">
        <v-flex xs12 sm10 md8 offset-sm1 offset-md2 mb-3>
		<v-layout row v-if="error">
				<v-flex>
					<app-alert @dismissed="onDismissed" :text="error.message"></app-alert>
				</v-flex>
			</v-layout>
		<v-card class="text-xs-center">
		  <div>
            <p><h3>Frissíteni akarja az email címét?</h3></p>
          </div>
		  <v-form
			ref="form2"
			v-model="valid2">
			<v-layout>
				<v-flex sm10 md10 offset-sm1 mb-3>
				<v-text-field
					name="email"
					label="Email cím"
					id="email"
					v-model="email">
                </v-text-field>
			    <v-btn
					:disabled="!valid2"
					color="success"
					@click="emailfrissit">
					Email frissítése &nbsp;
					<i class="material-icons">refresh</i>
		        </v-btn>  
                </v-flex>
            </v-layout>
		    </v-form>
            <div class="text-xs-center">
                <p>Megjegyzés: A művelet végrehajtásához frissen bejelentkezett állapotban hajtható végre!</p>
            </div>
			<br>
            <div class="text-xs-center">
                <p><h3>Frissíteni akarja a jelszavát?</h3></p>
                     <v-btn
						color="info"
						@click="onLogout">
						Kijelentkezés &nbsp;
                        <v-icon>exit_to_app</v-icon>
                      </v-btn>
            </div>
			<br>
            <div class="text-xs-center">
                <p>Megjegyzés: A művelet végrehajtásához jelentkezzen ki, majd kattintson az új jelszó igénylése gombra!</p>
            </div>
			<br>
            <div class="text-xs-center">
                <p><h3>Törölni szeretné a hozzáférést?</h3></p>
                      <v-btn
						:disabled="!valid2"
						color="error"
						@click="felhasznalotorol">
					    Hozzáférés törlése &nbsp;
						<i class="material-icons">delete</i>
		        </v-btn>
            </div>
			<br>
            <div class="text-xs-center">
                <p>Megjegyzés: A művelet végrehajtásához frissen bejelentkezett állapotban hajtható végre!</p>
				<br>
            </div>
		</v-card>
      </v-flex>
    </v-layout>
  </v-container>
</template>

<script>

  export default {
    data () {
      return {
        email: '',
		valid2: true,
		emailRules: [
        v => !!v || 'Az email mező nem maradhat üresen!',
        v => /.+@.+/.test(v) || 'Érvénytelen email formátum!'
		]
	  
      }
    },
	
	watch: {
      user (value) {
        if (value == null || value == undefined) {
          this.$router.push('/bejelentkezes')
        }
      }
    },
	
    computed: {
		user(){
			return this.$store.getters.user;
		},
		error () {
			return this.$store.getters.error
		}
    },
	
    mounted () {
      this.$store.dispatch('ellenorzes')
    },
	
    methods: {
			onDismissed () {
				this.$store.commit('setError', null)
			},
			AuthStateChanged(){
				
			},
			emailfrissit(){
				
			},
			felhasznalotorol () {
				this.$store.commit('logout')
			},
			onLogout () {
				this.$store.dispatch('logout')
			}
		}
		
		}
</script>