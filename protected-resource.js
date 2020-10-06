const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const jwt = require("jsonwebtoken")
const { timeout } = require("./utils")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/user-info', (req, res) => {
	const { authorization } = req.headers
	if (!authorization) {
		res.status(401).send("Error: not authorized")
		return
	}
	const payload = authorization.split(" ")[1];
	try {
		const verifedPayload = jwt.verify(payload, config.publicKey, {algorithms: ["RS256"]});
		const scopesArray = verifedPayload.scope.split(" ")
		const scopes = scopesArray.map(element => {
			return element.replace("permission:", "")
		})
		const resJSON = {};
		scopes.forEach(element => {
			resJSON[element] = users[verifedPayload.userName][element]
		})
		res.json(resJSON)
	} catch (error) {
		res.status(401).send("Error: not authorized")
		return
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
