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
              <form @submit.prevent="onSignup">
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
                    <v-text-field
                      name="confirmPassword"
                      label="Jelszó megerősítése"
                      id="confirmPassword"
                      v-model="confirmPassword"
                      type="password"
					  autocomplete="off"
                      :rules="[comparePasswords]"></v-text-field>
                  </v-flex>
                </v-layout>
                <v-layout row>
                  <v-flex xs12>
                    <v-checkbox
						v-model="agreement"
						label="Egyetértek az adatvédelmi irányelvekkel és a szolgáltatás feltételeivel."
						required
						autocomplete="off">
					</v-checkbox>
                    </div>
                  </v-flex>
                </v-layout>
                <v-layout row>
                  <v-flex xs12>
                    <div class="text-xs-center">
                      <v-btn round round color="red" dark  type="submit" :disabled="loading" :loading="loading">
                        Regisztráció
                        <v-icon right>lock_open</v-icon>
                        <span slot="loader" class="custom-loader">
                          <v-icon light>cached</v-icon>
                         </span>
                      </v-btn>
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
        confirmPassword: '',
        agreement: false
      }
    },
    computed: {
      comparePasswords () {
        return this.password !== this.confirmPassword ? 'A jelszavak nem egyeznek!' : true﻿
      },
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
    watch: {
      user (value) {
        if (value !== null && value !== undefined) {
          this.$router.push('/tesztsorozat')
        }
      }
    },
    methods: {
      onSignup () {
        this.$store.dispatch('signUserUp', {email: this.email, password: this.password})
      },
      onDismissed () {
        this.$store.commit('setError', null)
      }
    },
	mounted() {
		this.$store.dispatch('ellenorzes')
	},
  }
</script>