"use strict"
const port = process.env.SERVER_PORT
const backend = `http://localhost:${port}`
const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const cors = require('cors')
const compression = require("compression")
const helmet = require('helmet')
const morgan = require("morgan")
const usersroutes = require('./usersroutes')

const options = {dotfiles: 'allow'}
//const frontend = __dirname + '/tesztsorozat/dist/'
//const elearning = __dirname + '/host/elearning/dist/'
//const szemelyes = __dirname + '/host/szemelyes/dist/'

/*
app.use(cors({  
    origin: [`${backend}`],
    methods: ["GET", "POST", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}))
*/

app.use(cors())
app.use(helmet())
app.use(morgan("common"))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: false}))
app.use(compression())

//app.use(express.static(elearning,options))
app.use(express.static(frontend,options))
app.use('/tesztsorozat',express.static(frontend))
//app.use('/',express.static(elearning))
//app.use('/szemelyes',express.static(szemelyes))

app.use('/felhasznalok', usersroutes)

app.use((req, res, next) => {
	const error = new Error('Page not found!')
	error.status = 404
	next(error)
})

app.use((error, req, res, next) => {
	res.status(error.status || 500).json({
		message: error.message})
})

module.exports = app;