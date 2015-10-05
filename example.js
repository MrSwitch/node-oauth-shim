// Demonstation of integration
var oauthshim = require('./index.js'),
	express = require('express');

var app = express();

// Define a path where to put this OAuth Shim
app.all('/proxy', oauthshim);

// Create a key value list of {client_id => client_secret, ...}
var creds = {};

// Set credentials
if (process.env.YAHOO_ID) creds[process.env.YAHOO_ID] = process.env.YAHOO_SECRET;
if (process.env.TWITTER_ID) creds[process.env.TWITTER_ID] = process.env.TWITTER_SECRET;

// Initiate the shim with Client ID's and secret, e.g.
oauthshim.init(creds);

// Set application to list on PORT
app.listen(process.env.PORT);

console.log('OAuth Shim listening on ' + process.env.PORT);
