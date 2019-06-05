"use strict"
const fs = require('fs')
const express = require('express')
const router = express.Router()
const mysql = require('mysql')
const sql = require('./databaseconnection')
const bcrypt = require('bcrypt')
const jwt = require("jsonwebtoken")
const {validatebody, validateparams, schemas } = require('./model')
const checkauth = require('./check-auth')

router.get(/osszesfelhasznaloleker/, checkauth, (req, res, next) => {
	let lekerdezes = 'SELECT ??, ?? FROM ??'
	let inserts = ['id', 'email', 'users']
	lekerdezes = mysql.format(lekerdezes, inserts)
    sql.query(lekerdezes,
        (err, dl) => {
            if (err) {
				return res.status(500).json({
					error: err
			})
            } else {
                res.send(dl)
            }
        })
})

router.get(/sajatfelhasznaloleker/, checkauth, (req, res, next) => {
	const email = jwt.verify(req.headers.token.split(' ')[1], fs.readFileSync("./private.pem")).email
	let lekerdezes = 'SELECT ??, ?? FROM ?? WHERE ?? = ?'
	let inserts = ['id','email', 'users', 'email', email]
	lekerdezes = mysql.format(lekerdezes, inserts)
    sql.query(lekerdezes,
        (err, dl) => {
            if (err) {
				return res.status(500).json({
					error: err
			})
            } else {
                res.send(dl)
            }
        })
})

router.post(/regisztracio/, validatebody(schemas.schema1), (req, res, next) => {	
	let lekerdezes = 'SELECT ??, ?? FROM ?? WHERE ?? = ?'
	let inserts = ['id', 'email', 'users','email',req.body.email]
	lekerdezes = mysql.format(lekerdezes, inserts)
	sql.query(lekerdezes,
		(err, user) => {
			if (err) {
				return res.status(500).json({
					error: err
				})
			} else {
				if(!user.length){
					bcrypt.hash(req.body.password, 10, (err, hash) => {
						if(err){
							return res.status(500).json({
								error: err
							})
						} else {
							let lekerdezes = 'INSERT INTO ?? (??, ??, ??) VALUES (?, ?, ?)'
							let inserts = ['users','id','email','password', 'NULL', req.body.email, hash]
							lekerdezes = mysql.format(lekerdezes, inserts)
							sql.query(lekerdezes,(err, dl) => {
								if (err) {
									return res.status(500).json({
										error: err
									})
								} else {
									res.status(201).json({
										message:'User is created!'})
								}
							})
						}
					})
				} else {
					res.status(409).json({
						message:'This user is already exists!'})
				}
			}
		})	
})

router.post(/bejelentkezes/, validatebody(schemas.schema1), (req, res, next) => {	
	let lekerdezes = 'SELECT * FROM ?? WHERE ?? = ?'
	let inserts = ['users','email',req.body.email]
	lekerdezes = mysql.format(lekerdezes, inserts)
	sql.query(lekerdezes,(err, user) => {
			if (err) {
				return res.status(500).json({
					error: err
				})
			} else {
				if(user.length < 1){
					
					res.status(401).json({
						message:'Auth failed 1!'})
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
								fs.readFileSync('./private.pem'),
								{
									expiresIn: "2h"
								})
								return res.status(200).json({
									message: 'Sikeres hitelesítés!',
									token: token})
							} else {
								res.status(401).json({
									message:'Auth failed 2!'})
							}
						}
					})
				}
			}
		})
})

router.delete(/sajatfelhasznalotorol/, checkauth, (req, res, next) => {
	const email = jwt.verify(req.headers.token.split(' ')[1], fs.readFileSync("./private.pem")).email
	let lekerdezes = 'DELETE FROM ?? WHERE ?? = ?'
	let inserts = ['users', 'email', email]
	lekerdezes = mysql.format(lekerdezes, inserts)
    sql.query(lekerdezes,
        (err, dl) => {
            if (err) {
				return res.status(500).json({
					error: err
			})
            } else {
				res.status(200).json({
					message: 'User is deleted!'
      });
            }
        })
})

module.exports=router