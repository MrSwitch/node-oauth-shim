//
// Node-OAuth-Shim
// A RESTful API for interacting with OAuth1 and 2 services.
//
// @author Andrew Dodson
// @since July 2013

var https = require('https');
var http = require('http');
var url = require('url');
var qs = require('querystring');

var oauth = require('./oauth.js');
var proxy = require('./proxy.js');


// Wrap HTTP/HTTPS calls
function request(req,data,callback){
	var r = ( req.protocol==='https:' ? https : http ).request( req, function(res){
		var buffer = '';
		res.on('data', function(data){
			buffer += data;
		});
		res.on('end', function(){
			callback(null,res,buffer);
		});
	});
	r.on('error', function(err){
		callback(err);
	});
	if(data){
		r.write(data);
	}
	r.end();
	return r;
}



//
// Export a new instance of the API
module.exports = new (function(){

	// Add the modules
	var services = {};

	// Define self
	var self = this;

	// token=>secret lookup
	var _token_secrets = {};

	// Debug flag
	this.debug = false;

	//
	// Define the environments
	//
	this.init = function(obj){
		services = this.utils.merge(services, obj);
	};

	//
	// Login
	//
	this.login = function(p, callback){

		// Take the obj and make a call to the server
		if(	p.oauth && p.oauth.version === 1 ){
			return;
		}

/*
		opts.path = 'http://' + opts.host + ':' + opts.port + opts.path;
		opts.headers = opts.headers||{};
		opts.headers.host = opts.host;
		opts.host = '127.0.0.1';
		opts.port = 8888;
*/
		self.getCredentials( p.client_id || p.id, function(response){

			if(!response){
				return callback({
					error : "required_credentials",
					error_message  : "Could not find the credentials for signing this request, ensure that the correct client_id is passed",
					state : p.state || ''
				});
			}

			// Make the OAuth2 request
			var post = null;
			if(p.code){
				post = {
					code : p.code,
					client_id : p.client_id || p.id,
					client_secret : response,
					grant_type : 'authorization_code',
					redirect_uri : encodeURIComponent(p.redirect_uri)
				};
			}
			else if(p.refresh_token){
				post = {
					refresh_token : p.refresh_token,
					client_id : p.client_id || p.id,
					client_secret : response,
					grant_type : 'refresh_token',
				};
			}

			// Get the grant_url
			var grant_url = p.grant_url || p.grant || (p.oauth ? p.oauth.grant : false  );

			if(!grant_url){
				return callback({
					error : "required_grant",
					error_message  : "Missing parameter grant_url",
					state : p.state || ''
				});
			}

			self.utils.log("OAUTH2-GRANT-REQUEST", grant_url, post);

			// Convert the post object literal to a string
			post = self.utils.param(post, function(r){return r;});

			// Create the request
			var r = url.parse( grant_url );
			r.method = 'POST';
			r.headers = {
				'Content-length': post.length,
				'Content-type':'application/x-www-form-urlencoded'
			};

			//opts.body = post;
			request( r, post, function(err,res,body){

				var data = {};

				if(body){
					self.utils.log(body);
					try{
						data = JSON.parse(body);
					}
					catch(e){
						try{
							data = self.utils.param(body.toString('utf8', 0, body.length));
						}
						catch(e2){
							self.utils.log("Crap, grant response fubar'd");
						}
					}
				}

				// Check responses
				if(err||!body||(!("access_token" in data)&&!("error" in data))){
					if(!data||typeof(data)!=='object'){
						data = {};
					}
					data.error = "invalid_grant";
					if(err){
						data.error_message = "Could not find the authenticating server, "+grant_url;
					}
					else{
						data.error_message = "Could not get a sensible response from the authenticating server, "+grant_url;
					}
				}
				else if("access_token" in data&&!("expires_in" in data)){
					data.expires_in = 3600;
				}

				if(p.state){
					data.state = p.state || '';
				}

				// If the refresh token was on the original request lets return it.
				if( p.refresh_token && !data.refresh_token ){
					data.refresh_token = p.refresh_token;
				}

				callback(data);
			});
		});

	};


	//
	// Listen
	// Bind to an existing server listener
	//
	this.listen = function(server, requestPathname){

		// Store old Listeners
		var oldListeners = server.listeners('request');
		server.removeAllListeners('request');

		server.on('request', function (req, res) {

			// Lets let something else handle this.
			// Trigger all oldListeners
			function passthru(){
				for (var i = 0, l = oldListeners.length; i < l; i++) {
					oldListeners[i].call(server, req, res);
				}
			}

			// If the request is limited to a given path, here it is.
			if( requestPathname && requestPathname !== url.parse(req.url).pathname ){
				passthru();
				return;
			}

			//
			self.request(req,res);

		});
	};


	//
	// Request
	// Defines the callback from the server listener
	this.request = function(req,res){

		// if the querystring includes
		// An authentication "code",
		// client_id e.g. "1231232123",
		// response_uri, "1231232123",
		var p = self.utils.param(url.parse(req.url).search);
		var state = p.state;


		// Has the parameters been stored in the state attribute?
		try{
			// decompose the p.state, redefine p
			p = self.utils.merge( p, JSON.parse(p.state) );
			p.state = state; // set this back to the string
		}
		catch(e){
		}

		self.utils.log("REQUEST", p);

		//
		// Process, pass the request the to be processed,
		// The returning function contains the data to be sent
		function redirect(path, hash){

			// Overwrite intercept
			if("interceptRedirect" in self){
				self.interceptRedirect(path,hash);
			}

			var url = path + (hash ? '#'+ self.utils.param( hash ) : '');

			self.utils.log("REDIRECT", url );

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

			self.utils.log("RESPONSE-SERVE", body );

			res.writeHead(200, { 'Access-Control-Allow-Origin':'*' });
			res.end( body ,"utf8");
		}



		//
		// OAUTH2
		//
		if( ( p.code || p.refresh_token ) && p.redirect_uri ){

			self.login( p, function(response){

				// Redirect page
				// With the Auth response, we need to return it to the parent
				if(p.state){
					response.state = p.state || '';
				}
				redirect( p.redirect_uri, response);
				return;

			});
			return;
		}


		//
		// OAUTH1
		//
		else if( ( p.redirect_uri && p.oauth && parseInt(p.oauth.version,10) === 1 ) || p.token_url || p.oauth_token ){

			self.location = url.parse("http"+(req.connection.encrypted?"s":'')+'://'+req.headers.host+req.url);

			self.loginOAuth1(p, function(path,hash){
				redirect(path,hash);
			});

			return;
		}

		//
		// SUBSEQUENT SIGNING OF REQUESTS
		// Previously we've been preoccupoed with handling OAuth authentication/
		// However OAUTH1 also needs every request to be signed.
		//
		else if( p.access_token && p.path ){

			//
			// The access_token is of the format which can be decomposed
			//
			var token = p.access_token.match(/^([^:]+)\:([^@]+)@(.+)$/);
			var path = p.path;


			// errr
			var buffer = proxy.buffer(req);

			self.getCredentials( token[3], function(client_secret){

				if(client_secret){
					path = oauth.sign( p.path, {
						oauth_token: token[1],
						oauth_consumer_key : token[3]
					}, client_secret, token[2], null, (p.method||req.method).toUpperCase(), p.data?JSON.parse(p.data):null);
				}

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
	this.getCredentials = function(id, callback){

		callback( id ? services[id] : false );

	};


	//
	// OAuth 1
	// Thi handles the OAuth1 authentication flow
	//
	this.loginOAuth1 = function(p,callback){

		//
		// Get the Authorization path
		//
		// p = self.utils.merge(services[p.network], p);
		var	path,
			token_secret;

		var opts = {
			oauth_consumer_key : p.client_id
		};


		//
		// Refresh token?
		// Does this include an access token?
		if(p.access_token){
			// Disect access_token
			var token = p.access_token.match(/^([^:]+)\:([^@]+)@(.+)$/);
			if(token){

				// Assign the token
				p.oauth_token = token[0];
				token_secret = token[1];

				// Grap the refresh token and add it to the opts if it exists.
				if(p.refresh_token){
					opts.oauth_session_handle = p.refresh_token;
				}
			}
		}

		//
		// OAUTH 1: FIRST STEP
		// The oauth_token has not been provisioned.
		//
		if(!p.oauth_token){

			// Change the path to be that of the intiial handshake
			path = (p.request_url || (p.oauth?p.oauth.request:null));

			if(!path){
				return callback( p.redirect_uri, {
					error : "required_request_url",
					error_message : "A request_url is required",
					state : p.state || ''
				});
			}


			//
			// Create the URL of this service
			// We are building up a callback URL which we want the client to easily be able to use.

			// Callback
			var oauth_callback = p.redirect_uri + (p.redirect_uri.indexOf('?')>-1?'&':'?') + self.utils.param({
				proxy_url : self.location.protocol + '//'+ self.location.host + self.location.pathname,
				state     : p.state || '',
				token_url : p.token_url || p.oauth.token,
				client_id : p.client_id
			}, function(r){
				// Encode all the parameters
				return encodeURIComponent(r);
			});

			// Version 1.0a requires the oauth_callback parameter for signing the request
			if( (p.version || p.oauth.version ) ==='1.0a'){
				// Define the OAUTH CALLBACK Parameters
				opts.oauth_callback = oauth_callback;
			}

		}
		else{

			//
			// SECOND STEP
			// The provider has provisioned a temporary token
			//

			// Change the path to be that of the Providers token exchange
			path = p.token_url || (p.oauth?p.oauth.token:null);

			if(!path){
				return callback( p.redirect_uri, {
					error : "required_token_url",
					error_message : "A token_url is required to authenticate the oauth_token",
					state : p.state || ''
				});
			}


			// Check that there is a token
			opts.oauth_token = p.oauth_token;
			if(p.oauth_verifier){
				opts.oauth_verifier = p.oauth_verifier;
			}

			// If token secret has not been supplied by an access_token in case of a refresh
			// Get secret from temp storage
			if(!token_secret&&p.oauth_token in _token_secrets){
				token_secret = _token_secrets[p.oauth_token];
			}

			// If no secret is given, panic
			if(!token_secret){
				return callback( p.redirect_uri, {
					error : (!p.oauth_token?"required":"invalid")+"_oauth_token",
					error_message : "The oauth_token "+ (!p.oauth_token?" is required":" was not recognised" ),
					state : p.state || ''
				});
			}
		}


		//
		// Find the client secret
		// Get the client secret
		//
		self.getCredentials( p.client_id, function(client_secret){

			if(!client_secret){
				callback( p.redirect_uri, {
					error : "invalid_credentials",
					error_message : "Credientials were not recognised",
					state : p.state || ''
				});
				return;
			}

			// Sign the request using the application credentials
			var signed_url = oauth.sign( path, opts, client_secret, token_secret || null);

			// Requst
			var r = url.parse(signed_url);

			self.utils.log("OAUTH-REQUEST-URL", signed_url);

			// Make the call
			request( r, null, function(err,res,data){

				if(err){
					/////////////////////////////
					// The server failed to respond
					/////////////////////////////
					return callback( p.redirect_uri, {
						error : "server_error",
						error_message : "Unable to connect to "+signed_url,
						state : p.state || ''
					});
				}

				self.utils.log("OAUTH-RESPONSE-DATA",data.toString(),res.statusCode);

				var json = {};
				try{
					json = JSON.parse(data.toString());
				}
				catch(e){
					try{
						json = self.utils.param(data.toString());
					}
					catch(ee){
						console.log("ERROR", "REQUEST: "+signed_url, "RESPONSE: "+data.toString() );
					}
				}

				if(json.error||res.statusCode>=400){

					// Error
					if(!json.error){
						//self.utils.log(json);
						json = {
							error: json.oauth_problem|| "auth_failed",
							error_message : res.statusCode + " could not authenticate",
							state : p.state || ''
						};
					}
					callback( p.redirect_uri, json );
				}

				// Was this a preflight request
				else if(!opts.oauth_token){
					// Step 1

					// Store the oauth_token_secret
					if(json.oauth_token_secret){
						_token_secrets[json.oauth_token] = json.oauth_token_secret;
					}

					// Great redirect the user to authenticate
					var url = (p.auth_url||p.oauth.auth);
					callback( url + (url.indexOf('?')>-1?'&':'?') + self.utils.param({
						oauth_token : json.oauth_token,
						oauth_callback : oauth_callback
					}) );
				}

				else{
					// Step 2
					// Construct the access token to send back to the client
					json.access_token = json.oauth_token +':'+json.oauth_token_secret+'@'+p.client_id;
					json.state = p.state || '';

					delete json.oauth_token;
					delete json.oauth_token_secret;

					// Optionally return the refresh_token and expires_in if given
					if(json.oauth_expires_in){
						json.expires_in = json.oauth_expires_in;
						delete json.oauth_expires_in;
					}

					// Optionally standarize any refresh token
					if(json.oauth_session_handle){
						json.refresh_token = json.oauth_session_handle;
						delete json.oauth_session_handle;

						if(json.oauth_authorization_expires_in){
							json.refresh_expires_in = json.oauth_authorization_expires_in;
							delete json.oauth_authorization_expires_in;
						}
					}

					// Return the entire response object to the client
					// Often included is ID's, name etc which can save additional requests
					callback( p.redirect_uri, json );
				}

				return;
			});
		});
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

	this.utils = {

		// Log activity
		log : function(){
			if(!self.debug){
				return;
			}
			var args = Array.prototype.slice.call(arguments);
			for(var i=0;i<args.length;i++){
				console.log("============");
				console.log(args[i]);
			}
		},

		//
		// Param
		// Explode/Encode the parameters of an URL string/object
		// @param string s, String to decode
		//
		param : function (s, encode){

			var b,
				a = {},
				m;

			if(typeof(s)==='string'){

				var decode = encode || decodeURIComponent;

				m = s.replace(/^[\#\?]/,'').match(/([^=\/\&]+)=([^\&]+)/g);

				if(m){
					for(var i=0;i<m.length;i++){
						b = m[i].split('=');
						a[b[0]] = decode( b[1] );
					}
				}
				return a;
			}
			else {
				var o = s;
				encode = encode || encodeURIComponent;
			
				a = [];

				for( var x in o ){if(o.hasOwnProperty(x)){
					if( o.hasOwnProperty(x) && o[x] !== null ){
						a.push( [x, o[x] === '?' ? '?' : encode(o[x]) ].join('=') );
					}
				}}

				return a.join('&');
			}
		},


		//
		// merge
		// recursive merge two objects into one, second parameter overides the first
		// @param a array
		//
		merge : function(a,b){
			var x,r = {};
			if( typeof(a) === 'object' && typeof(b) === 'object' ){
				for(x in a){if(a.hasOwnProperty(x)){
					r[x] = a[x];
					if(x in b){
						r[x] = this.merge( a[x], b[x]);
					}
				}}
				for(x in b){if(b.hasOwnProperty(x)){
					if(!(x in a)){
						r[x] = b[x];
					}
				}}
			}
			else{
				r = b;
			}
			return r;
		},

		//
		// Clone
		// Recursively clones an object
		clone : function(obj){
			return this.merge({},obj);
		},


		//
		// filter
		// @param sorts the returning resultset
		//
		filter : function (o){
			if(['string','number'].indexOf(typeof(o))!==-1){
				return o;
			}

			var r = (Array.isArray(o)?[]:{});

			for(var x in o){ if(o.hasOwnProperty(x)){
				if(o[x]!==null){
					if( typeof(x) === 'number' ){
						r.push( this.filter( o[x] ) );
					}
					else{
						r[x] = this.filter(o[x]);
					}
				}
			}}
			return r;
		},

		//
		// empty
		// Checks whether an Array has length 0, an object has no properties etc
		empty : function(o){
			if(this.isObject(o)){
				return Object.keys(o).length === 0;
			}
			if(this.isArray(o)){
				return o.length===0;
			}
			else{
				return !!o;
			}
		},

		//
		// isObject
		isObject : function(o){
			return Object.prototype.toString.call( o ) === '[object Object]';
		},

		//
		// isArray
		isArray : function(o){
			return Array.isArray(o);
		},

		//
		// Args utility
		// Makes it easier to assign parameters, where some are optional
		// @param o object
		// @param a arguments
		//
		args : function(o,args){

			var p = {},
				i = 0,
				t = null, // tag
				m = null, // match
				x = null;
			
			// define x
			for(x in o){if(o.hasOwnProperty(x)){
				break;
			}}

			// Passing in hash object of arguments?
			// Where the first argument can't be an object
			if((args.length===1)&&(typeof(args[0])==='object')&&o[x]!='o!'){
				// return same hash.
				return args[0];
			}

			// else loop through and account for the missing ones.
			for(x in o){if(o.hasOwnProperty(x)){

				t = typeof( args[i] );
				m = o[x];

				if( ( typeof( m ) === 'function' && m.test(args[i]) ) ||
					( typeof( m ) === 'string' && (
						( m.indexOf('s') > -1 && t === 'string' ) ||
						( m.indexOf('o') > -1 && t === 'object' && !Array.isArray(args[i]) ) ||
						( m.indexOf('i') > -1 && t === 'number' ) ||
						( m.indexOf('a') > -1 && t === 'object' && Array.isArray(args[i]) ) ||
						( m.indexOf('f') > -1 && t === 'function' )
					) )
				){
					p[x] = args[i++];
				}
				
				else if( typeof( m ) === 'string' && m.indexOf('!') > -1 ){
					this.log("Whoops! " + x + " not defined");
					return false;
				}
			}}
			return p;
		}
	};
})();