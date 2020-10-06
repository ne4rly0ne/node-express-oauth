const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/authorize', (req, res) => {
	const { client_id, scope } = req.query
	if (!client_id || !scope) {
		res.status(401).send("Error: client not authorized")
		return
	}
	const client = clients[client_id]
	if (!client) {
		res.status(401).send("Error: client not authorized")
		return
	}

	if (typeof scope !== "string" || !containsAll(client.scopes, scope.split(" "))) {
		res.status(401).send("Error: client not authorized")
		return
	}

	const requestId = randomString(); 
	requests[requestId] = req.query;

	res.render("login", {
		client,
		scope,
		requestId
	})
})

app.post('/approve', (req, res) => {
	const { userName, password, requestId } = req.body;
	if (!userName || users[userName] !== password) {
		res.status(401).send("Error: user cannot login")
		return
	}
	const clientReq = requests[requestId]
	delete requests[requestId]
	if (!clientReq) {
		res.status(401).send("Error: user cannot login")
		return
	} 

	const code = randomString();

	authorizationCodes[code] = {
		clientReq,
		userName
	}

	const myURL = new URL(clientReq.redirect_uri);
	myURL.searchParams.append('code', code)
	myURL.searchParams.append('state', clientReq.state);
	res.redirect(myURL.href)
})

app.post('/token', (req, res) => {
	const { authorization } = req.headers;
	const { code } = req.body
	if (!authorization) {
		res.status(401).send("Error: not authorized")
		return
	}
	const decoded = decodeAuthCredentials(authorization);
	const client = clients[decoded.clientId];
	if(client.clientSecret !== decoded.clientSecret) {
		res.status(401).send("Error: not authorized")
		return
	}
	const authObject = authorizationCodes[code];
	delete authorizationCodes[code]
	if (!authObject) {
		res.status(401).send("Error: not authorized")
		return
	} 

	const { userName, clientReq } = authObject;

	const token = jwt.sign(
		{
			userName: userName, 
			scope: clientReq.scope
		}, 
		config.privateKey, 
		{ 
			algorithm: 'RS256', expiresIn: 300,
			issuer: "http://localhost:" + config.port
		}
	)

	res.json({
		access_token: token,
		token_type: "Bearer",
		scope: clientReq.scope
	});
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
