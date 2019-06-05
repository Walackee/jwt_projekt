const mysql = require('mysql')

const sql = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
})

sql.connect((err) => {
	if(err){
		console.log(err)
	} else {
		console.log("Sikeres csatlakozás az adatbázishoz!")
	}
});

module.exports = sql;