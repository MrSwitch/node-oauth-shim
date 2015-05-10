//
// Node-OAuth-Shim
// A RESTful API for interacting with OAuth1 and 2 services.
//
// @author Andrew Dodson
// @since July 2013


var url = require('url');

var qs = require('./utils/qs');
var merge = require('./utils/merge');
var param = require('./utils/param');


var sign = require('./sign.js');
var proxy = require('./proxy.js');

var oauth2 = require('./oauth2');
var oauth1 = require('./oauth1');


// Add the modules
var services = {};



//
// Export a new instance of the API
module.exports = function( req, res, next ){
	return module.exports.request( req, res, next );
};




// Set pretermined client-id's and client-secret
module.exports.init = function(obj){
	services = merge(services, obj);
};



//
// Request
// Compose all the default operations of this component
//
module.exports.request = function( req, res, next ){

	var self = module.exports;

	return self.interpret( req, res,
			self.proxy.bind( self, req, res,
			self.redirect.bind( self, req, res,
			self.unhandled.bind( self, req, res, next ) ) ) );
};



//
// Interpret the oauth login
// Append data to the request object to hand over to the 'redirect' handler
//
module.exports.interpret = function( req, res, next ){

	var self = module.exports;

	// if the querystring includes
	// An authentication "code",
	// client_id e.g. "1231232123",
	// response_uri, "1231232123",
	var p = param(url.parse(req.url).search);
	var state = p.state;


	// Has the parameters been stored in the state attribute?
	try{
		// decompose the p.state, redefine p
		p = merge( p, JSON.parse(p.state) );
		p.state = state; // set this back to the string
	}
	catch(e){}

	// Define the options
	req.oauthshim = {
		options : p
	};

	// Generic formatting `redirect_uri` is of the correct format
	if ( typeof p.redirect_uri === 'string' && !p.redirect_uri.match(/^[a-z]+:\/\//i) ) {
		p.redirect_uri = '';
	}


	//
	// OAUTH2
	//
	if( ( p.code || p.refresh_token ) && p.redirect_uri ){

		login( p, oauth2, function( session ){

			// Redirect page
			// With the Auth response, we need to return it to the parent
			if(p.state){
				session.state = p.state || '';
			}

			// OAuth Login
			redirect( req, p.redirect_uri, session, next );
		});

		return;
	}


	//
	// OAUTH1
	//
	else if( p.redirect_uri && ( ( p.oauth && parseInt(p.oauth.version,10) === 1 ) || p.token_url || p.oauth_token ) ) {

		p.location = url.parse("http"+(req.connection.encrypted?"s":'')+'://'+req.headers.host+req.url);

		login( p, oauth1, function(path, session){
			redirect( req, path, session, next );
		});


		return;
	}

	// Move on
	else if(next){
		next();
	}

};




//
// Proxy
// Signs/Relays requests
//
module.exports.proxy = function(req, res, next){

	var p = param(url.parse(req.url).search);


	//
	// SUBSEQUENT SIGNING OF REQUESTS
	// Previously we've been preoccupoed with handling OAuth authentication/
	// However OAUTH1 also needs every request to be signed.
	//
	if( p.access_token && p.path ){

		// errr
		var buffer = proxy.buffer(req);

		signRequest( (p.method||req.method), p.path, p.data, p.access_token, proxyHandler.bind(null, req, res, next, p, buffer) );

		return;
	}
	else if(p.path){

		proxyHandler( req, res, next, p, undefined, p.path );

		return;
	}

	else if( next ){
		next();
	}
};



//
// Redirect Request
// Is this request marked for redirect?
//
module.exports.redirect = function( req, res, next ){

	var self = module.exports;

	if( req.oauthshim && req.oauthshim.redirect ){

		var hash = req.oauthshim.data;
		var path = req.oauthshim.redirect;

		path += ( hash ? '#'+ param( hash ) : '' );

		res.writeHead( 302, {
			'Access-Control-Allow-Origin':'*',
			'Location': path
		});

		res.end();
	}
	else if(next){
		next();
	}
};



//
// unhandled
// What to return if the request was previously unhandled
// 
module.exports.unhandled = function( req, res, next ){

	var p = param(url.parse(req.url).search);

	serveUp( res, {
		error : {
			code : 'invalid_request',
			message : 'The request is unrecognised'
		}
	}, p.callback );

};



//
// getCredentials
// Given a network name and a client_id, returns the client_secret
//
module.exports.getCredentials = function(id, callback){

	callback( id ? services[id] : false );

};




//
//
//
//
// UTILITIES
//
//
//
//



//
// Login
// OAuth2
//
function login(p, handler, callback){

	module.exports.getCredentials( p.client_id || p.id, function(client_secret){

		p.client_secret = client_secret;

		handler( p, callback );

	});

}

//
// Sign
//

function signRequest( method, path, data, access_token, callback ){

	var token = access_token.match(/^([^:]+)\:([^@]+)@(.+)$/);

	if(!token){

		// If the access_token exists, append it too the path
		if( access_token ){
			path = qs(path, {
				access_token : access_token
			});
		}

		callback( path );
		return;
	}
	
	module.exports.getCredentials( token[3], function( client_secret ){

		if(client_secret){
			path = sign( path, {
				oauth_token: token[1],
				oauth_consumer_key : token[3]
			}, client_secret, token[2], null, method.toUpperCase(), data?JSON.parse(data):null);
		}

		callback(path);

	});
}



//
// Process, pass the request the to be processed,
// The returning function contains the data to be sent
function redirect(req, path, hash, next){

	req.oauthshim = req.oauthshim || {};
	req.oauthshim.data = hash;
	req.oauthshim.redirect = path;

	if( next ){
		next();
	}
}


//
// Serve Up 
//

function serveUp(res, body, jsonp_callback){

	if(typeof(body)==='object'){
		body = JSON.stringify(body, null, 2);
	}
	else if(typeof(body)==='string'&&jsonp_callback){
		body = "'"+body+"'";
	}

	if(jsonp_callback){
		body = jsonp_callback + "(" + body + ")";
	}

	res.writeHead(200, { 'Access-Control-Allow-Origin':'*' });
	res.end( body ,"utf8");
}




function proxyHandler(req, res, next, p, buffer, path){

	// Define Default Handler
	// Has the user specified the handler
	// determine the default`
	if(!p.then){
		if(req.method==='GET'){
			if(!p.method||p.method.toUpperCase()==='GET'){
				// Change the location
				p.then = 'redirect';
			}
			else{
				// return the signed path
				p.then = 'return';
			}
		}
		else{
			// proxy the request through this server
			p.then = 'proxy';
		}
	}


	//
	if(p.then==='redirect'){
		// redirect the users browser to the new path
		redirect(req, path, null, next);
	}
	else if(p.then==='return'){
		// redirect the users browser to the new path
		serveUp(res, path, p.callback);
	}
	else{
		var options = url.parse(path);
		options.method = p.method ? p.method.toUpperCase() : req.method;

		//
		// Proxy
		proxy.proxy(req, res, options, buffer);
	}
}