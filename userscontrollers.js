const fs = require('fs')
const mysql = require('mysql')
const sql = require('./databaseconnection')
const bcrypt = require('bcrypt')
const jwt = require("jsonwebtoken")
const secret = fs.readFileSync('./private.pem')
const saltrounds = 10

exports.osszesfelhasznalokeler = (req, res, next) => {
	let lekerdezes = 'SELECT ??, ?? FROM ??'
	let inserts = ['id', 'email', 'users']
	lekerdezes = mysql.format(lekerdezes, inserts)
    sql.query(lekerdezes,
        (err, dl) => {
            if (err) {
				return res.status(500).json({message: err.sqlMessage})
            } else {
                res.send(dl)
            }
        })
}

exports.sajatfelhasznaloleker = (req, res, next) => {
	const email = jwt.verify(req.headers.token.split(' ')[1], secret).email
	let lekerdezes = 'SELECT ??, ?? FROM ?? WHERE ?? = ?'
	let inserts = ['id','email', 'users', 'email', email]
	lekerdezes = mysql.format(lekerdezes, inserts)
    sql.query(lekerdezes,
        (err, dl) => {
            if (err) {
				return res.status(500).json({message: err.sqlMessage})
            } else {
                res.send(dl)
            }
        })
}

exports.regisztracio = (req, res, next) => {	
	let lekerdezes = 'SELECT ??, ?? FROM ?? WHERE ?? = ?'
	let inserts = ['id', 'email', 'users','email',req.body.email]
	lekerdezes = mysql.format(lekerdezes, inserts)
	sql.query(lekerdezes,
		(err, user) => {
			if (err) {
				return res.status(500).json({message: err.sqlMessage})
			} else {
				if(!user.length){
					bcrypt.hash(req.body.password, saltrounds, (err, hash) => {
						if(err){
							return res.status(500).json({message: err})
						} else {
							let lekerdezes = 'INSERT INTO ?? (??, ??, ??) VALUES (?, ?, ?)'
							let inserts = ['users','id','email','password', 'NULL', req.body.email, hash]
							lekerdezes = mysql.format(lekerdezes, inserts)
							sql.query(lekerdezes,(err, dl) => {
								if (err) {
									return res.status(500).json({message: err.sqlMessage})
								} else {
									res.status(201).json({message:'Felhasználó létrehozva!'})
								}
							})
						}
					})
				} else {
					res.status(409).json({message:'Ez a felhasználó már létezik!'})
				}
			}
		})	
}

exports.bejelentkezes = (req, res, next) => {	
	let lekerdezes = 'SELECT * FROM ?? WHERE ?? = ?'
	let inserts = ['users','email',req.body.email]
	lekerdezes = mysql.format(lekerdezes, inserts)
	sql.query(lekerdezes,(err, user) => {
			if (err) {
				return res.status(500).json({message: err.sqlMessage})
			} else {
				if(user.length < 1){
					res.status(401).json({message:'Sikertelen azonosítás 1!'})
				} else {
					bcrypt.compare(req.body.password, user[0].password, (err, result) => {
						if(err){
							res.status(401).json({
								error: err})
						} else {
							if(result){
								const token = jwt.sign({
									email: user[0].email
								},
								secret,
								{
									expiresIn: "1h"
								})
								return res.status(200).json({
									message: 'Sikeres azonosítás!',
									token: token})
							} else {
								res.status(401).json({message:'Nincs megfelelő jogosultsága 2!'})
							}
						}
					})
				}
			}
		})
}

exports.sajatfelhasznalotorol = (req, res, next) => {
	const email = jwt.verify(req.headers.token.split(' ')[1], secret).email
	let lekerdezes = 'DELETE FROM ?? WHERE ?? = ?'
	let inserts = ['users', 'email', email]
	lekerdezes = mysql.format(lekerdezes, inserts)
    sql.query(lekerdezes,
        (err, dl) => {
            if (err) {
				return res.status(500).json({message: err.sqlMessage})
            } else {
				res.status(200).json({message: 'A felhasználó törölve!'})
            }
        })
}