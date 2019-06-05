<template>
  <v-container>
    <v-layout row class="mb-2">
        <v-flex xs12 sm10 md8 offset-sm1 offset-md2 mb-3>
		<v-layout row v-if="error">
			<v-flex>
				<app-alert @dismissed="onDismissed" :text="error.message"></app-alert>
			</v-flex>
		</v-layout>
		<v-card>
		  <div class="text-xs-center">
            <h2>Ez lesz a főoldal!</h2>
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
	  
      }
    },
    computed: {
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
			}
		}
		
		}
</script>