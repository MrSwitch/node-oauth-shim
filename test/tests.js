//
// OAuth Shim Tests
// Run from root with using command 'npm test'
//
// @author Andrew Dodson
// @since July 2013
//
//

////////////////////////////////
// Dependiencies
////////////////////////////////

var oauth = require('../oauth'),
	oauthshim = require('../index'),
	querystring = require('querystring'),
	fs = require('fs'),
	path = require('path');


// Setup a test server
var request = require('supertest'),
	express = require('express');
var app = express();

// include this adds 'should' to all javascript objects...
// Indeed i too thought extending native objects was bad
// ... where there's a way there's a will!
require('should');


////////////////////////////////
// SETUP SHIM LISTENING
////////////////////////////////

oauthshim.debug = false;

oauthshim.init({
	// OAuth 1
	'oauth_consumer_key' : 'oauth_consumer_secret',

	// OAuth 2
	'client_id' : 'client_secret'
});


// Start listening
app.all('/proxy', oauthshim.request );


////////////////////////////////
// SETUP REMOTE SERVER
// This reproduces a third party OAuth and API Server
////////////////////////////////

var connect = require('connect');
var remoteServer = connect(), srv;
var test_port = 3333;

beforeEach(function(){
	srv = remoteServer.listen(test_port);
});

// tests here
afterEach(function(){
	srv.close();
});


////////////////////////////////
// TEST OAUTH2 SIGNING
////////////////////////////////


var oauth2codeExchange = querystring.stringify({
	expires_in : 'expires_in',
	access_token : 'access_token',
	state : 'state'
});


remoteServer.use('/oauth/grant', function(req,res){

	res.writeHead(200);
	res.write(oauth2codeExchange);
	res.end();
});


describe('OAuth2 exchanging code for token,', function(){

	var query = {};

	beforeEach(function(){
		query = {
			'grant_url' : 'http://localhost:'+test_port+'/oauth/grant',
			'code' : '123456',
			'client_id' : 'client_id',
			'redirect_uri' : 'http://localhost:'+test_port+'/response',
			'state' : "state"
		};
	});

	function redirect_uri(o){
		var hash = [];
		for(var x in o){
			hash.push(x + '=' + o[x]);
		}
		return new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '#' + hash.join('&') );
	}

	it("should return an access_token, and redirect back to redirect_uri", function(done){

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', query.redirect_uri + '#' + oauth2codeExchange )
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should fail if the grant_url is missing, and redirect back to redirect_uri", function(done){

		delete query.grant_url;

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'required_grant',
				error_message : '([^&]+)',
				state: query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should fail if the grant_url is invalid, and redirect back to redirect_uri", function(done){

		query.grant_url = "http://localhost:5555";

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'invalid_grant',
				error_message : '([^&]+)',
				state: query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});


	it("should error with required_credentials if the client_id was not provided", function(done){

		delete query.client_id;

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'required_credentials',
				error_message : '([^&]+)',
				state: query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should error with invalid_credentials if the supplied client_id had no associated client_secret", function(done){

		query.client_id = "unrecognised";

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'invalid_credentials',
				error_message : '([^&]+)',
				state: query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});
	
});


// /////////////////////////////
// OAuth2 Excahange refresh_token for access_token
// /////////////////////////////

describe('OAuth2 exchange refresh_token for access token', function(){

	var query = {};

	beforeEach(function(){
		query = {
			'grant_url' : 'http://localhost:'+test_port+'/oauth/grant',
			'refresh_token' : '123456',
			'client_id' : 'client_id',
			'redirect_uri' : 'http://localhost:'+test_port+'/response',
			'state' : "state"
		};
	});

	function redirect_uri(o){
		var hash = [];
		for(var x in o){
			hash.push(x + '=' + o[x]);
		}
		return new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '#' + hash.join('&') );
	}

	it("should redirect back to redirect_uri with an access_token and refresh_token", function(done){

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', query.redirect_uri + '#' + oauth2codeExchange+"&refresh_token=123456" )
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});
	
});




////////////////////////////////
// REMOTE SERVER AUTHENTICATION
////////////////////////////////

// Step 1: Return oauth_token & oauth_token_secret
remoteServer.use('/oauth/request', function(req,res){

	res.writeHead(200);
	var body = querystring.stringify({
		oauth_token : 'oauth_token',
		oauth_token_secret : 'oauth_token_secret'
	});
	res.write(body);
	res.end();
});

// Step 3: Return verified token and secret
remoteServer.use('/oauth/token', function(req,res){

	res.writeHead(200);
	var body = querystring.stringify({
		oauth_token : 'oauth_token',
		oauth_token_secret : 'oauth_token_secret'
	});
	res.write(body);
	res.end();
});



////////////////////////////////
// TEST OAUTH SIGNING
////////////////////////////////

describe('OAuth authenticate', function(){

	var query = {};

	beforeEach(function(){
		query = {
			request_url : 'http://localhost:'+test_port+'/oauth/request',
			token_url : 'http://localhost:'+test_port+'/oauth/token',
			auth_url : 'http://localhost:'+test_port+'/oauth/auth',
			version : '1.0a',
			state : '',
			client_id : 'oauth_consumer_key',
			redirect_uri : 'http://localhost:'+test_port+'/'
		};
	});

	function redirect_uri(o){
		var hash = [];
		for(var x in o){
			hash.push(x + '=' + o[x]);
		}
		return new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '#' + hash.join('&') );
	}


	it("should correctly sign a request", function(){
		var callback = 'http://location.com/?wicked=knarly&redirect_uri='+
					encodeURIComponent("http://local.knarly.com/hello.js/redirect.html"+
						"?state="+encodeURIComponent(JSON.stringify({proxy:"http://localhost"})));
		var sign = oauth.sign('https://api.dropbox.com/1/oauth/request_token', {'oauth_consumer_key':'t5s644xtv7n4oth', 'oauth_callback':callback}, 'h9b3uri43axnaid', '', '1354345524');
		sign.should.equal("https://api.dropbox.com/1/oauth/request_token?oauth_callback=http%3A%2F%2Flocation.com%2F%3Fwicked%3Dknarly%26redirect_uri%3Dhttp%253A%252F%252Flocal.knarly.com%252Fhello.js%252Fredirect.html%253Fstate%253D%25257B%252522proxy%252522%25253A%252522http%25253A%25252F%25252Flocalhost%252522%25257D&oauth_consumer_key=t5s644xtv7n4oth&oauth_nonce=1354345524&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1354345524&oauth_version=1.0&oauth_signature=7hCq53%2Bcl5PBpKbCa%2FdfMtlGkS8%3D");
	});

	it("should redirect users to the path defined as `auth_url`", function(done){

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', new RegExp( query.auth_url.replace(/\//g,'\\/') + '\\?oauth_token\\=oauth_token\\&oauth_callback\\=' + encodeURIComponent(query.redirect_uri).replace(/\//g,'\\/') ) )
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should return an #error if given a wrong request_url", function(done){

		query.request_url = 'http://localhost:'+test_port+'/oauth/brokenrequest';

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'auth_failed',
				error_message : '([^&]+)',
				state : query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should return an Error 'server_error' if given a wrong domain", function(done){

		query.request_url = 'http://localhost:'+(test_port+1)+'/wrongdomain';

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'server_error',
				error_message : '([^&]+)',
				state : query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should return Error 'required_request_url' if request_url is missing", function(done){

		delete query.request_url;

		request(app)
			.get('/proxy?'+querystring.stringify( query ))
			.expect('Location', redirect_uri({
				error : 'required_request_url',
				error_message : '([^&]+)',
				state : query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});


	it("should error with required_credentials if the client_id was not provided", function(done){

		delete query.client_id;

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'required_credentials',
				error_message : '([^&]+)',
				state: query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should error with invalid_credentials if the supplied client_id had no associated client_secret", function(done){

		query.client_id = "unrecognised";

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'invalid_credentials',
				error_message : '([^&]+)',
				state: query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});
	

});


////////////////////////////////
// TEST OAUTH EXCHANGE TOKEN
////////////////////////////////

describe('OAuth exchange token', function(){

	var query = {};

	beforeEach(function(){
		query = {
			token_url : 'http://localhost:'+test_port+'/oauth/token',
			oauth_token : 'oauth_token',
			redirect_uri : 'http://localhost:'+test_port+'/',
			client_id : 'oauth_consumer_key',
			state : 'state'
		};
	});

	function redirect_uri(o){
		var hash = [];
		for(var x in o){
			hash.push(x + '=' + o[x]);
		}
		return new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '#' + hash.join('&') );
	}


	it("should exchange an oauth_token, and return an access_token", function(done){

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				access_token : encodeURIComponent('oauth_token:oauth_token_secret@'+query.client_id)
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});


	it("should return an #error if given an erroneous token_url", function(done){

		query.token_url = 'http://localhost:'+test_port+'/oauth/brokentoken';

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'auth_failed',
				error_message : '([^&]+)',
				state : query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should return an #error if token_url is missing", function(done){

		delete query.token_url;

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'required_token_url',
				error_message : '([^&]+)',
				state : query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should return an #error if the oauth_token is wrong", function(done){

		query.oauth_token = 'boom';

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', redirect_uri({
				error : 'invalid_oauth_token',
				error_message : '([^&]+)',
				state : query.state
			}))
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

});











////////////////////////////////
// REMOTE SERVER API
////////////////////////////////

remoteServer.use('/api/', function(req,res){

	// If an Number is passed on the URL then return that number as the StatusCode
	if( req.url.replace(/^\//,'') > 200 ){
		res.writeHead(req.url.replace(/^\//,'')*1);
		res.end();
		return;
	}

	res.setHeader('x-test-url', req.url);
	res.setHeader('x-test-method', req.method);
	res.writeHead(200);

//	console.log(req.headers);

	var buf='';
	req.on('data', function(data){
		buf+=data;
	});

	req.on('end', function(){
		////////////////////
		// TAILOR THE RESPONSE TO MATCH THE REQUEST
		////////////////////
		res.write([req.method, req.headers.header, buf].filter(function(a){return !!a;}).join('&'));
		res.end();
	});

});



// Test path
var api_url = 'http://localhost:'+test_port+'/api/',
	access_token = 'token_key:token_secret@oauth_consumer_key';




////////////////////////////////
// TEST PROXY
////////////////////////////////

describe('Proxying requests with a shimed access_token', function(){



	///////////////////////////////
	// REDIRECT THE AGENT
	///////////////////////////////

	it("should correctly sign and return a 302 redirection, implicitly", function(){

		request(app)
			.get('/proxy?access_token='+ access_token +'&path=' + api_url)
			.expect('Location', new RegExp( api_url + '\\?oauth_consumer_key\\=oauth_consumer_key\\&oauth_nonce\\=.+&oauth_signature_method=HMAC-SHA1\\&oauth_timestamp=[0-9]+\\&oauth_token\\=token_key\\&oauth_version\\=1\\.0\\&oauth_signature\\=.+\\%3D') )
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
			});
	});

	it("should correctly sign and return a 302 redirection, explicitly", function(){

		request(app)
			.get('/proxy?access_token='+ access_token +'&then=redirect&path=' + api_url)
			.expect('Location', new RegExp( api_url + '\\?oauth_consumer_key\\=oauth_consumer_key\\&oauth_nonce\\=.+&oauth_signature_method=HMAC-SHA1\\&oauth_timestamp=[0-9]+\\&oauth_token\\=token_key\\&oauth_version\\=1\\.0\\&oauth_signature\\=.+\\%3D') )
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
			});
	});


	///////////////////////////////
	// RETURN THE SIGNED REQUEST
	///////////////////////////////

	it("should correctly return a signed uri", function(){

		request(app)
			.get('/proxy?then=return&access_token='+ access_token +'&path='+ api_url)
			.expect(200, new RegExp( api_url + '\\?oauth_consumer_key\\=oauth_consumer_key\\&oauth_nonce\\=.+&oauth_signature_method=HMAC-SHA1\\&oauth_timestamp=[0-9]+\\&oauth_token\\=token_key\\&oauth_version\\=1\\.0\\&oauth_signature\\=.+\\%3D') )
			.end(function(err, res){
				if (err) throw err;
			});
	});

	it("should correctly return signed uri in a JSONP callback", function(){

		request(app)
			.get('/proxy?then=return&access_token='+ access_token +'&path='+ api_url+'&callback=myJSON')
			.expect(200, new RegExp( 'myJSON\\(([\'\"])'+api_url + '\\?oauth_consumer_key\\=oauth_consumer_key\\&oauth_nonce\\=.+&oauth_signature_method=HMAC-SHA1\\&oauth_timestamp=[0-9]+\\&oauth_token\\=token_key\\&oauth_version\\=1\\.0\\&oauth_signature\\=.+\\%3D(\\1)\\)') )
			.end(function(err, res){
				if (err) throw err;
			});
	});

	it("should accept the method and correctly return a signed uri accordingly", function(){

		request(app)
			.get('/proxy?then=return&method=POST&access_token='+ access_token +'&path='+ api_url)
			.expect(200, new RegExp( api_url + '\\?oauth_consumer_key\\=oauth_consumer_key\\&oauth_nonce\\=.+&oauth_signature_method=HMAC-SHA1\\&oauth_timestamp=[0-9]+\\&oauth_token\\=token_key\\&oauth_version\\=1\\.0\\&oauth_signature\\=.+\\%3D') )
			.end(function(err, res){
				if (err) throw err;
			});
	});


	///////////////////////////////
	// PROXY REQUESTS - SIGNED
	///////////////////////////////

	it("should correctly sign the path and proxy GET requests", function(done){
		request(app)
			.get('/proxy?then=proxy&access_token='+ access_token +'&path='+ api_url)
			.expect("GET")
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should correctly sign the path and proxy POST body", function(done){

		request(app)
			.post('/proxy?then=proxy&access_token='+ access_token +'&path='+ api_url)
			.send("POST_DATA")
			.expect('Access-Control-Allow-Origin', '*')
			.expect("POST&POST_DATA")
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should correctly sign the path and proxy POST asynchronously", function(done){

		oauthshim.getCredentials = function(id, callback){
			setTimeout(function(){
				callback('oauth_consumer_secret');
			}, 1000);
		};

		request(app)
			.post('/proxy?then=proxy&access_token='+ access_token +'&path='+ api_url)
			.attach("file", './test/tests.js')
			.expect('Access-Control-Allow-Origin', '*')
			.expect(/^POST\&(\-\-.*?)[\s\S]*(\1)\-\-$/)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});
});



describe("Proxying unsigned requests", function(){

	var access_token = 'token';

	///////////////////////////////
	// PROXY REQUESTS - UNSIGNED
	///////////////////////////////

	it("should append the access_token to the path - if it does not conform to an OAuth1 token, and needs not be signed", function( done ){
		request(app)
			.get('/proxy?then=proxy&access_token='+ access_token +'&path='+ api_url)
			.expect("GET")
			.expect("x-test-url", /access_token\=token/ )
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});


	it("should correctly return a 302 redirection", function(){

		request(app)
			.get('/proxy?path=' + api_url)
			.expect('Location', api_url)
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
			});
	});

	it("should correctly proxy GET requests", function(done){
		request(app)
			.get('/proxy?then=proxy&path='+ api_url)
			.expect("GET")
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should correctly proxy POST requests", function(done){
		request(app)
			.post('/proxy?then=proxy&path='+ api_url)
			.send("POST_DATA")
			.expect('Access-Control-Allow-Origin', '*')
			.expect("POST&POST_DATA")
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should correctly proxy multipart POST requests", function(done){
		request(app)
			.post('/proxy?then=proxy&path='+ api_url)
			.attach("file", './test/tests.js')
			.expect('Access-Control-Allow-Origin', '*')
			.expect(/^POST\&(\-\-.*?)[\s\S]*(\1)\-\-$/)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	/*
	it("should correctly pass through headers", function(done){
		request(app)
			.post('/proxy?then=proxy&path='+ api_url)
			.set('header', 'header')
			.expect('Access-Control-Allow-Origin', '*')
			.expect("POST&header")
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	}); */

	it("should correctly proxy DELETE requests", function(done){
		request(app)
			.del('/proxy?then=proxy&path='+ api_url)
			.expect('Access-Control-Allow-Origin', '*')
			.expect("DELETE")
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should handle invalid paths", function(done){
		var fake_url = "http://localhost:45673/";
		request(app)
			.post('/proxy?then=proxy&path='+ fake_url)
			.send("POST_DATA")
			.expect('Access-Control-Allow-Origin', '*')
			.expect(502)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should return server errors", function(done){

		request(app)
			.post('/proxy?then=proxy&path='+ api_url + "401" )
			.send("POST_DATA")
			.expect('Access-Control-Allow-Origin', '*')
			.expect(401)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});


	it("should return a JSON error object if absent path parameter", function(done){

		request(app)
			.post('/proxy')
			.expect('Access-Control-Allow-Origin', '*')
			.expect(200)
			.end(function(err, res){
				var obj = JSON.parse(res.text);
				if( obj.error.code !== "invalid_request" ) throw new Error("Not failing gracefully");
				done();
			});
	});

});