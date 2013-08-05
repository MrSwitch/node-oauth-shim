//
// Proxy Server
// -------------
// Proxies requests with the Access-Control-Allow-Origin Header
//
// @author Andrew Dodson
//

var url = require('url');
var http=require('http');
var https=require('https');

var request = function(opts, callback){
	var req = (opts.protocol === 'https:'? https : http ).request(opts, callback);
	req.on('error', function(){
		callback();
	});
	return req;
};

//
// @param req				- Request Object
// @param options || url	- Map request to this
// @param res				- Response, bind response to this
module.exports = function(req,options,res){

	if(typeof(options==='string')){
		options = url.parse(options);
		options.headers = req.headers;
		options.method = req.method;
	}

	options.agent = false;

	var connector = request(options, function(serverResponse) {
		var headers = {};
		if(serverResponse){
			headers = serverResponse.headers;
		}
		headers['Access-Control-Allow-Origin'] = "*";
		res.writeHeader( serverResponse && serverResponse.statusCode || 502, headers);
		if(serverResponse){
			serverResponse.pipe(res, {end:true});
		}
		else{
			res.end();
		}
	});

	req.pipe(connector, {end:true});
};