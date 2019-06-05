<template>
  <v-container>
    <v-layout row v-if="error">
      <v-flex xs12 sm6 offset-sm3>
        <app-alert @dismissed="onDismissed" :text="error.message"></app-alert>
      </v-flex>
    </v-layout>
    <v-layout row>
      <v-flex xs12 sm6 offset-sm3>
        <v-card>
          <v-card-text>
            <v-container>
              <form @submit.prevent="onSignin" autocomplete="off">
                <v-layout row>
                  <v-flex xs12>
                    <v-text-field
                      name="email"
                      label="Email"
                      id="email"
                      v-model="email"
                      type="email"
					  autocomplete="off"
                      required></v-text-field>
                  </v-flex>
                </v-layout>
                <v-layout row>
                  <v-flex xs12>
                    <v-text-field
                      name="password"
                      label="Jelszó"
                      id="password"
                      v-model="password"
                      type="password"
					  autocomplete="off"
                      required></v-text-field>
                  </v-flex>
                </v-layout>
				<v-layout row>
                  <v-flex xs12>
                    <v-checkbox
						v-model="checkbox"
						label="Egyetértek az adatvédelmi irányelvekkel és a szolgáltatás feltételeivel."
						required
						autocomplete="off">
					</v-checkbox>
                  </v-flex>
                </v-layout>
				
                <v-layout row>
                  <v-flex xs12>
                    <div class="text-xs-center">
                    <v-btn round color="red" dark type="submit" :disabled="loading" :loading="loading">
                      Bejelentkezés &nbsp;
                      <v-icon right>lock_open</v-icon>
                      <span slot="loader" class="custom-loader">
                        <v-icon light>cached</v-icon>
                       </span>
                    </v-btn>
                    <br>
                    </div>
                    <br>
                    <div class="text-xs-center">
                      <p>Elfelejtette a jelszavát?</p>
                      <v-btn round color="primary" dark :disabled="loading" :loading="loading" @click.prevent="onResetPassword">Új jelszó igénylése
                        <v-icon right dark>email</v-icon>
                        <span slot="loader" class="custom-loader">
                        <v-icon light>cached</v-icon>
                       </span>
                      </v-btn>
                      <br>
                      <br>
                      <p>Tekintse meg az emailjeit és kövesse az utasításokat!</p>
                    </div>
                  </v-flex>
                </v-layout>
              </form>
            </v-container>
          </v-card-text>
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
        password: '',
		checkbox: false
      }
    },
	
    computed: {
      user () {
        return this.$store.getters.user
      },
      error () {
        return this.$store.getters.error
      },
      loading () {
        return this.$store.getters.loading
      }
    },
	
	mounted(){
		this.$store.dispatch('ellenorzes')
	},
	
    methods: {
      onSignin () {
        this.$store.dispatch('signUserIn', {email: this.email, password: this.password})
      },
      onResetPassword () {
        if (this.email === '') {
          this.$store.dispatch('setError', {message: 'Az email mező kitöltése kötelező!'})
        } else {}{
			this.$store.dispatch('resetPasswordWithEmail', {email: this.email})
		}
      },
      onDismissed () {
        this.$store.commit('setError', null)
      }
    }
  }
</script>