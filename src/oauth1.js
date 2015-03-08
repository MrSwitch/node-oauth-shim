//
// OAuth1 authentication
// ----------------------
//

var param = require('./utils/param');
var sign = require('./sign');
var url = require('url');
var request = require('./utils/request');

// token=>secret lookup
var _token_secrets = {};


module.exports = function(p, callback){



	//
	// Get the Authorization path
	//
	// p = merge(services[p.network], p);
	var	path,
		token_secret,
		client_secret = p.client_secret,
		version = p.version || ( p.oauth ? p.oauth.version : 1 );

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
		var oauth_callback = p.redirect_uri + (p.redirect_uri.indexOf('?')>-1?'&':'?') + param({
			proxy_url : p.location.protocol + '//'+ p.location.host + p.location.pathname,
			state     : p.state || '',
			token_url : p.token_url || p.oauth.token,
			client_id : p.client_id
		}, function(r){
			// Encode all the parameters
			return encodeURIComponent(r);
		});

		// Version 1.0a requires the oauth_callback parameter for signing the request
		if( version ==='1.0a'){
			// Define the OAUTH CALLBACK Parameters
			opts.oauth_callback = oauth_callback;

			// TWITTER HACK
			// See issue https://twittercommunity.com/t/oauth-callback-ignored/33447
			if( path.match('api.twitter.com') ){
				opts.oauth_callback = encodeURIComponent(oauth_callback);
			}
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
	

	if(!client_secret){
		callback( p.redirect_uri, {
			error : ( p.client_id ? "invalid" : "required" ) + "_credentials",
			error_message : "Credentials were not recognised",
			state : p.state || ''
		});
		return;
	}

	// Sign the request using the application credentials
	var signed_url = sign( path, opts, client_secret, token_secret || null);

	// Requst
	var r = url.parse(signed_url);

	//log("OAUTH-REQUEST-URL", signed_url);

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

		//log("OAUTH-RESPONSE-DATA",data.toString(),res.statusCode);

		var json = {};
		try{
			json = JSON.parse(data.toString());
		}
		catch(e){
			try{
				json = param(data.toString());
			}
			catch(ee){
				console.error("ERROR", "REQUEST: "+signed_url, "RESPONSE: "+data.toString() );
			}
		}

		if(json.error||res.statusCode>=400){

			// Error
			if(!json.error){
				//log(json);
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

			var params = {
				oauth_token : json.oauth_token
			};

			// Version 1.0a requires the oauth_callback parameter for signing the request
			if( version !== '1.0a' ){
				// Define the OAUTH CALLBACK Parameters
				params.oauth_callback = oauth_callback;
			}

			// Great redirect the user to authenticate
			var url = (p.auth_url||p.oauth.auth);
			callback( url + (url.indexOf('?')>-1?'&':'?') + param(params) );
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
};