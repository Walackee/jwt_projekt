const joi = require('@hapi/joi')

module.exports = {
	validatebody: (schema) => {
		return (req, res, next) => {
			const result = joi.validate(req.body, schema)
			if(result.error){
				return res.status(400).json({
					message: result.error.details[0].message
				})
			}
			// req.value.body ellenőrzése req.body helyett
			if(!req.value){
				req.value = {}
			}
			req.value['body'] = result.value
			next()
		}
	},
	validateparams: (schema) => {
		return (req, res, next) => {
			const result = joi.validate(req.params, schema)
			if(result.error){
				return res.status(400).json({
					message: result.error.details[0].message
				})
			}
			next()
		}
	},
	
	schemas: {
		schema1: joi.object().keys({
			password: joi.string().error(() => 'A jelszó formátuma nem string!')
						 .max(15).error(() => 'A string hossza maximum 15 karakter lehet!')
						 .required().error(() => 'A jelszó hiányzik!'),
			email: joi.string().error(() => 'Az email hiányzik!')
					  .email().error(() => 'Helytelen email formátum!')
					  .min(1).error(() => 'A string hossza minimum 1!')
					  .max(30).error(() => 'A string hossza maximum 30 karakter lehet!')
					  .required().error(() => 'Az email hiányzik!')
		}),
		schema2: joi.object().keys({
			id: joi.number().required().error(() => 'Az azonosító hiányzik!')
		})	
	}
}