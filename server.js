const dotenv = require('dotenv')
dotenv.config({path:'./.env'})
const http = require('http')
const app = require('./app')
const port = process.env.SERVER_PORT
const server = http.createServer(app)
server.listen(port)
console.log(`A szerverünk a ${port} porton fut!`)