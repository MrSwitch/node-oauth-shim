# OAuth-shim
This node module provides a "shim" service for clientside web apps adopting serverside OAuth2 or OAuth1 authentication but fighting to keep it all the browser, and shims the tedious dog legging through servers that has become OAuth1's curse.


## Use case

Popular API's like Twitter, Dropbox and Yahoo require this server-to-server authentication paradigm. What oauthshim does is set up a RESTful service which shims up these web API's. This is used by clientside libraries like [HelloJS](http://adodson.com/hello.js) as a fallback to keep everything running in the client.

## Demo

[https://auth-server.herokuapp.com](https://auth-server.herokuapp.com) is a service which utilizes this package. You can register your own Application Key and Secret there if you dont want to set your own up. But for production you shouldn't rely on that service.


## Installing on the server

Install the package

	npm install oauth-shim


## Using with ExpressJS
	
	var oauthshim = require('oauth-shim'),
		express = require('express');

	var app = express();
	app.all('/oauthproxy', oauthshim.request);

	// Initiate the shim with Client ID's e.g.
	oauthshim.init({
		// key : Secret
		'12345' : 'secret678910',
		'abcde' : 'secretfghijk'
	});

	// Print request->response to console.
	oauthshim.debug = true;

The code above says apply the shim to all requests to the pathname `/oauthproxy`.

## Using with ConnectJS

Change `oauthshim.request` to `oauthshim.listen`


### Asynchronsly access secret

If you want to return clientID's asynchronosly (perhaps you want to look up from a database) then override the getCredentials method. Here's the basics e.g...

	oauthshim.getCredentials = function(id,callback){
		// Return
		if(id === '12345'){
			callback('secret678910');
		}
		if(id === 'abcde'){
			callback('secretfghijk');
		}
	}


## Authentication API

### Authentication OAuth 2.0

The OAuth2 flow for the shim starts after a web application sends a client out to a providers site to grant permissions. The response is an authorization code "[AUTH_CODE]" which is returned to your site, this needs to be exchanged for an Access Token. Your page then needs to send this code to an //auth-server with your client_id in exhchange for an access token, e.g.


	?redirect_uri=[REDIRECT_PATH]
	&code=[AUTH_CODE]
	&client_id=[APP_KEY]
	&state=[STATE]
	&grant_url=[PROVIDERS_OAUTH2_GRANT_URL]


The client will be redirected back to the location of [REDIRECT_PATH], with the contents of the server response as well as whatever was defined in the [STATE] in the hash. e.g...


	[REDIRECT_PATH]#state=[STATE]&access_token=ABCD1233234&expires=123123123



### Authentication OAuth 1.0 &amp; 1.0a

OAuth 1.0 has a number of steps so forgive the verbosity here. An app is required to make an initial request to the //auth-server, which in-turn initiates the authentication flow.


	?redirect_uri=[REDIRECT_PATH]
	&client_id=[APP_KEY]
	&request_url=[OAUTH_REQUEST_TOKEN_URL]
	&auth_url=[OAUTH_AUTHORIZATION_URL]
	&token_url=[OAUTH_TOKEN_URL]
	&state=[STATE]


The OAuthShim signs the client request and redirects the user to the providers login page defined by `[OAUTH_AUTHRIZATION_URL]`.

Once the user has signed in they are redirected back to a page on the developers app defined by `[REDIRECT_PATH]`. 

The provider should have included an oauth_callback parameter which was defined by //auth-server, this includes part of the path where the token can be returned for an access token. The total path response shall look something like this.


	[REDIRECT_PATH]
	?state=[STATE]
	&proxy_url=https://auth-server.herokuapp.com/proxy
	&client_id=[APP_KEY]
	&token_url=[OAUTH_TOKEN_URL]
	&oauth_token=abc12465


The page you defined locally as the `[REDIRECT_PATH]`, must then construct a call to //auth-server to exchange the unauthorized oauth_token for an access token. This would look like this...


	?oauth_token=abc12465
	&redirect_uri=[REDIRECT_PATH]
	&client_id=[APP_KEY]
	&state=[STATE]
	&token_url=[OAUTH_TOKEN_URL]


Finally the //auth-server returns the access_token to your redirect path and its the responsibility of your script to store this in the client in order to make subsequent API calls.

	[REDIRECT_PATH]#state=[STATE]&access_token=ABCD1233234&expires=123123123


This access token still needs to be signed via //auth-server every time an API request is made - read on...





## API: Signing API Requests

The OAuth 1.0 API requires that each request is uniquely signed with the application secret. This restriction was removed in OAuth 2.0, so only applied to OAuth1 endpoints.

### A simple GET Redirect

To sign a request to `[API_PATH]`, use the `[ACCESS_TOKEN]` returned in OAuth 1.0 above and send to the auth-server. 

	?access_token=[ACCESS_TOKEN]
	&path=[API_PATH]

The oauth shim signs and redirects the requests to the `[API_PATH]` e.g.

	[API_PATH]?oauth_token=asdf&oauth_consumer_key=asdf&...&oauth_signature=1234

If the initial request was other than a GET request, it will be proxied through the oauthshim by default. CORS headers would be added to the response from the end server.

### Signing a Request and returning the Signed Request URL

If the end server supports CORS and a lot of data is expected to be either sent or returned. The burded on the oauthshim can be lessened by merely returning the signed request url and handling the action elsewhere. 

	?access_token=[ACCESS_TOKEN]
	&path=[API_PATH]
	&then=return

### Proxying the Request
Conversely forcing the request to proxy through the oauthshim is achieved by applying the flag then=proxy. CORS headers are added to the response. This naturally is the slow route for data and is best avoided.

	?access_token=[ACCESS_TOKEN]
	&path=[API_PATH]
	&then=proxy


### Change the method and add callback for JSONP
Add a JSONP callback function and override the method. E.g.

	?access_token=[ACCESS_TOKEN]
	&path=[API_PATH]
	&then=return
	&method=post
	&callback=myJSONP


## Contributing

Don't forget to run the tests. 

	# Install the test dependencies.

	npm install -l

	# Run the tests, continuously

	npm test

	# Single

	mocha test


