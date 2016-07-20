var mysql = require('mysql');

var state = {
  pool: null
}

var configuration = {
  host: null,
  user: null,
  password: null,
  port: 3306,
  database: null,
  table: null
}

exports.init = function(config) {
  if(config.host !== undefined) configuration.host = config.host;
  if(config.user !== undefined) configuration.user = config.user;
  if(config.password !== undefined) configuration.password = config.password;
  if(config.port !== undefined) configuration.port = config.port;
  if(config.database !== undefined) configuration.database = config.database;
  if(config.table !== undefined) configuration.table = config.table;
}

exports.connect = function(mode) {
  if(state.pool === null) {
    state.pool = mysql.createPool({
      host: configuration.host,
      user: configuration.user,
      password: configuration.password,
      port: configuration.port,
      database: configuration.database
    })
  }
}


exports.get = function() {
  return state.pool
}

exports.getOAuthTokenSecret = function(client_id, oauth_token, callback){
  var pool = state.pool

  if(state.pool !== null){
    if(client_id !== undefined && oauth_token !== undefined) {
      sql = mysql.format('SELECT ' + configuration.table + '.clientid, ' + configuration.table + '.userid, ' + configuration.table + '.oauth_token, ' + configuration.table + '.oauth_token_secret, ' + configuration.table + '.screen_name, ' + configuration.table + '.x_auth_expires, ' + configuration.table + '.access_token FROM oauth WHERE ' + configuration.table + '.clientid = ? AND ' + configuration.table + '.oauth_token = ?',[client_id, oauth_token]);
      pool.query(sql, function(err, result) {
        if(err) throw err;
        var secret = null;
        if(result !== undefined && result[0] !== undefined && result[0].oauth_token_secret !== undefined) secret = result[0].oauth_token_secret;
        callback(secret);
      });
    } else {
      callback();
    }
  }

}

exports.storeCreds = function(credentials, callback){
  var pool = state.pool
  if(state.pool !== null){
    if(credentials.client_id !== undefined && credentials.oauth_token !== undefined) {
      var toDB = {};
      toDB.clientid = credentials.client_id;
      toDB.oauth_token = credentials.oauth_token;
      if(credentials.access_token !== undefined) toDB.access_token = credentials.access_token;
      if(credentials.userid !== undefined) toDB.userid = credentials.userid;
      if(credentials.oauth_token_secret !== undefined) toDB.oauth_token_secret = credentials.oauth_token_secret;
      if(credentials.screen_name !== undefined) toDB.screen_name = credentials.screen_name;
      if(credentials.x_auth_expires !== undefined) toDB.x_auth_expires = credentials.x_auth_expires;
      if(credentials.refresh_token !== undefined) toDB.refresh_token = credentials.refresh_token;

      sql = mysql.format('INSERT INTO `' + configuration.table + '` SET ? ON DUPLICATE KEY UPDATE ?', [toDB, toDB]);
      pool.query(sql, function(err, result) {
        if(err) throw err;
        if(callback !== undefined) callback();
      });
    }
  }
}

exports.prepare = function(sql, arr){
  return mysql.format(sql, arr)
}
