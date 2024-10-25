const { MongoClient } = require("mongodb")
const { v4: uuidv4 } = require("uuid")
const { WebSocketServer, WebSocket } = require('ws')
const jwt = require("jsonwebtoken")
var fs = require('fs');
var secretKey = fs.readFileSync('/run/secrets/app_secret', 'utf8');

const mongoURL = "mongodb://mongodb:27017"

async function insert(doc) {
    let client = null;
    try {
        doc['_id'] = uuidv4();
        client = new MongoClient(mongoURL);
        await client.connect()
        const db = client.db("messages").collection("messages");
        await db.insertOne(doc);
    } catch (error) {
        console.error("Error inserting document: ", error)
    } finally {
        if (client) {
            await client.close();
        }
    }
}

async function getLastMessages(roomId, count) {
    if (!count) {
        count = 5;
    }
    let client = null;
    try {
        client = new MongoClient(mongoURL);
        await client.connect()
        const db = client.db("messages");
        const q = {find: "messages", filter: {room: roomId.toString()}, limit: parseInt(count), sort:{timestamp:-1}};
        const result = await db.command(q);
        const r = result.cursor.firstBatch;
        return r;
    } catch (error) {
        console.error("Error inserting document: ", error)
    } finally {
        if (client) {
            await client.close();
        }
    }
}

function getQueryParam(path, name) {
    const queryParams = path.split("?", 2).pop().split("&").map(x => x.split("="));
    return queryParams.filter(x => x[0] == name).map(x => x[1])[0];
}

function auth(req) {
    try {
        const path = req.url;
        let cookie = req.headers["cookie"];
        const authToken = cookie.split(";").map(x => x.split("=")).filter(x => x[0] == "auth").map(x => x[1])[0];
        const roomToken = getQueryParam(path, "token");
        const results = {};
        let data = jwt.verify(roomToken, secretKey, options = {
            algorithms: ['HS256'],
        });

        let split = data.sub.split("-");
        if (split.length < 2 || split[0] != "R") {
            return null;
        }
        results["room"] = split[1];

        data = jwt.verify(authToken, secretKey, options = {
            algorithms: ['HS256'],
        });

        split = data.sub.split("-");
        if (split.length < 2 || split[0] != "U") {
            return null;
        }

        results["userId"] = split[1];
        console.log("successful auth for user " + results["userId"] + " and room " + results["room"]);
        return results;
    } catch (e) {
        console.log(e);
        console.log("failed authentication");
        return null;
    }
}

const connections = new Map()

const wss = new WebSocketServer({ port: 8801 })
wss.on('connection', (client, req) => {
    const authData = auth(req);
    if (!authData) {
        client.close();
        return;
    }

    if (!connections.get(authData.room)) {
        connections.set(authData.room, []);
    }
    connections.get(authData.room).push(client);
    console.log('New client connected');

    if (client.readyState === WebSocket.OPEN) {
        const count = getQueryParam(req.url, "count");
        getLastMessages(authData.room, count).then((messages) => {
            console.log(`distributing ${messages.length} messages...`)
            client.send(JSON.stringify(messages));
        });
    }


    client.on('message', (data) => {
        let msg = {};
        try {
            msg = JSON.parse(data.toString());
        } catch (error) {
            if (error instanceof SyntaxError) {
                console.error("Invalid JSON received:", data.toString());
            } else {
                console.error("Error parsing message:", error);
            }
            return;
        }

        let doc = {...msg, ...authData};

        console.log("Distributing message: " + JSON.stringify(doc));

        // Save chats
        insert(doc);

        // Send chats to all other relevant clients
        connections.get(doc.room).forEach(c => {
            if (c.readyState === WebSocket.OPEN) {
                c.send(JSON.stringify([doc]));
            }
        });
    })
    client.onerror = function () {
        console.log('websocket error')
    }

})
