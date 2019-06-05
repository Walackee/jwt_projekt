"use strict"
const express = require('express')
const router = express.Router()
const {validatebody, validateparams, schemas } = require('./validation')
const checkauth = require('./check-auth')
const userscontrollers = require('./userscontrollers')

router.get(/osszesfelhasznaloleker/, checkauth, userscontrollers.osszesfelhasznalokeler)
router.get(/sajatfelhasznaloleker/, validateparams(schemas.schema2), checkauth, userscontrollers.sajatfelhasznaloleker)
router.post(/regisztracio/, validatebody(schemas.schema1), userscontrollers.regisztracio)
router.post(/bejelentkezes/, validatebody(schemas.schema1), userscontrollers.bejelentkezes)
router.delete(/sajatfelhasznalotorol/, checkauth, userscontrollers.sajatfelhasznalotorol)

module.exports=router