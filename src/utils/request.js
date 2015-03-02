var https = require('https');
var http = require('http');

// Wrap HTTP/HTTPS calls
module.exports = function(req,data,callback){
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
};