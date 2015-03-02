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
module.exports = function( req, res ){
	return module.exports.request( req, res );
};


// Debug flag
module.exports.debug = false;


// Define the empty function to be called when a users signs in.
module.exports.onauthorization = null;


// Set pretermined client-id's and client-secret
module.exports.init = function(obj){
	services = merge(services, obj);
};



//
// Request
// Defines the callback from the server listener
module.exports.request = function(req,res){

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
	catch(e){
	}

	log("REQUEST", p);

	//
	// Process, pass the request the to be processed,
	// The returning function contains the data to be sent
	function redirect(path, hash){

		// Overwrite intercept
		if("interceptRedirect" in self){
			self.interceptRedirect(path,hash);
		}

		var url = path + (hash ? '#'+ param( hash ) : '');

		log("REDIRECT", url );

		res.writeHead(302, {
			'Access-Control-Allow-Origin':'*',
			'Location': url
		} );
		res.end();
	}

	function serveUp(body){

		if(typeof(body)==='object'){
			body = JSON.stringify(body, null, 2);
		}
		else if(typeof(body)==='string'&&p.callback){
			body = "'"+body+"'";
		}

		if(p.callback){
			body = p.callback + "(" + body + ")";
		}

		log("RESPONSE-SERVE", body );

		res.writeHead(200, { 'Access-Control-Allow-Origin':'*' });
		res.end( body ,"utf8");
	}



	//
	// OAUTH2
	//
	if( ( p.code || p.refresh_token ) && p.redirect_uri ){

		login( p, oauth2, function( session ){

			// trigger the authentication
			if( session && "access_token" in session && self.onauthorization){
				self.onauthorization( session );
			}

			// Redirect page
			// With the Auth response, we need to return it to the parent
			if(p.state){
				session.state = p.state || '';
			}
			redirect( p.redirect_uri, session );
			return;

		});
		return;
	}


	//
	// OAUTH1
	//
	else if( ( p.redirect_uri && p.oauth && parseInt(p.oauth.version,10) === 1 ) || p.token_url || p.oauth_token ){

		p.location = url.parse("http"+(req.connection.encrypted?"s":'')+'://'+req.headers.host+req.url);

		login( p, oauth1, function( path, hash ){

			// trigger the authentication
			if( hash && "access_token" in hash && self.onauthorization){
				self.onauthorization( hash );
			}

			redirect( path, hash );
		});


		return;
	}

	//
	// SUBSEQUENT SIGNING OF REQUESTS
	// Previously we've been preoccupoed with handling OAuth authentication/
	// However OAUTH1 also needs every request to be signed.
	//
	else if( p.access_token && p.path ){

		// errr
		var buffer = proxy.buffer(req);

		signRequest( (p.method||req.method), p.path, p.data, p.access_token, function( path ){

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
				redirect(path);
			}
			else if(p.then==='return'){
				// redirect the users browser to the new path
				serveUp(path);
			}
			else{
				var options = url.parse(path);
				options.method = p.method ? p.method.toUpperCase() : req.method;

				//
				// Proxy
				proxy.proxy(req, res, options, buffer);
			}
		});

		return;
	}
	else if(p.path){

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
			redirect(p.path);
		}
		else if(p.then==='return'){
			// redirect the users browser to the new path
			serveUp(p.path);
		}
		else{
			// Forward the whole request through a proxy
			// New request options
			var options = url.parse(p.path);
			options.method = p.method ? p.method.toUpperCase() : req.method;

			//
			// Proxy
			proxy.proxy(req, res, options);
		}
	}
	else{
		serveUp({
			error : {
				code : 'invalid_request',
				message : 'The request is unrecognised'
			}
		});
	}
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



// Log activity
function log(){
	if(!module.exports.debug){
		return;
	}
	var args = Array.prototype.slice.call(arguments);
	for(var i=0;i<args.length;i++){
		console.log("============");
		console.log(args[i]);
	}
}

