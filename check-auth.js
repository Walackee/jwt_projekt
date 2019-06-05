const fs = require('fs')
const jwt = require('jsonwebtoken')
const secret = fs.readFileSync("./private.pem")

module.exports = (req, res, next) => {
  if ((!req.headers.token || !req.headers.token.startsWith('Bearer '))) {
    return res.status(401).json({
		message: "Auth failed 3!"
	})
  }
  let idToken, something
  if (req.headers.token && req.headers.token.startsWith('Bearer ')) {
    idToken = req.headers.token.split(' ')[1]
  try {
    const decoded = jwt.verify(req.headers.token.split(' ')[1], secret)
    req.user = decoded
    next()
    return
  } catch (error) {
	  return res.status(401).json({
		message: "Auth failed 4!"
	})
  }
  }
}