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

beforeEach(function(){
	srv = remoteServer.listen(3000);
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
	access_token : 'access_token'
});


remoteServer.use('/oauth/grant', function(req,res){

	res.writeHead(200);
	res.write(oauth2codeExchange);
	res.end();
});


describe('OAuth2 exchanging code for token, ', function(){

	var query = {};

	beforeEach(function(){
		query = {
			'grant_url' : 'http://localhost:3000/oauth/grant',
			'code' : '123456',
			'client_id' : 'client_id',
			'redirect_uri' : 'http://localhost:3000/response'
		};
	});


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
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#error\\=required_grant' ) )
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
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#error\\=invalid_grant' ) )
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});


	it("should fail if the client_secret could not be determined, and redirect back to redirect_uri", function(done){

		delete query.client_id;

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#error\\=required_credentials' ) )
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
			request_url : 'http://localhost:3000/oauth/request',
			token_url : 'http://localhost:3000/oauth/token',
			auth_url : 'http://localhost:3000/oauth/auth',
			version : '1.0a',
			state : '',
			client_id : 'oauth_consumer_key',
			redirect_uri : 'http://localhost:3000/'
		};
	});


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

		query.request_url = 'http://localhost:3000/oauth/brokenrequest';

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#error\\=.*' ) )
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

	it("should return an #error if request_url is missing", function(done){

		delete query.request_url;

		request(app)
			.get('/proxy?'+querystring.stringify( query ))
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#error\\=.*' ) )
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
			token_url : 'http://localhost:3000/oauth/token',
			oauth_token : 'oauth_token',
			redirect_uri : 'http://localhost:3000/',
			client_id : 'oauth_consumer_key'
		};
	});


	it("should exchange an oauth_token, and return an access_token", function(done){

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#access_token\\=' +
									encodeURIComponent('oauth_token:oauth_token_secret@'+query.client_id) ) )
			.expect(302)
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});


	it("should return an #error if given an erroneous token_url", function(done){

		query.token_url = 'http://localhost:3000/oauth/brokentoken';

		request(app)
			.get('/proxy?'+querystring.stringify(query))
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#error\\=.*' ) )
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
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#error\\=required_token_url.*' ) )
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
			.expect('Location', new RegExp( query.redirect_uri.replace(/\//g,'\\/') + '\\#error\\=invalid_oauth_token.*' ) )
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

	res.writeHead(200);

	var buf='';
	req.on('data', function(data){
		buf+=data;
	});

	req.on('end', function(){
		////////////////////
		// TAILOR THE RESPONSE TO MATCH THE REQUEST
		////////////////////
		res.write([req.method, buf].join('&'));
		res.end();
	});

});



// Test path
var api_url = 'http://localhost:3000/api/',
	access_token = 'token_key:token_secret@oauth_consumer_key';




////////////////////////////////
// TEST PROXY
////////////////////////////////

describe('Proxying requests with a shimed access_token ', function(){



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
			.expect("GET&")
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
});



describe("Proxying unsigned requests ", function(){

	///////////////////////////////
	// PROXY REQUESTS - UNSIGNED
	///////////////////////////////

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
			.expect("GET&")
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

	it("should correctly proxy DELETE requests", function(done){
		request(app)
			.del('/proxy?then=proxy&path='+ api_url)
			.expect('Access-Control-Allow-Origin', '*')
			.expect("DELETE&")
			.end(function(err, res){
				if (err) throw err;
				done();
			});
	});

});