var mysql = require('mysql')

var state = {
  pool: null
}

var configuration = {
  host: null,
  user: null,
  password: null,
  port: 3306
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

exports.getCreds(client_id,oauth_token, callback){
  if(state.pool !== null){
    if(client_id !== undefined && oauth_token !== undefined) {
      var fromDB = {};
      fromDB.clientid = client_id;
      fromDB.oauth_token = oauth_token;
    }
    sql = 'SELECT ' + configuration.table + '.clientid, ' + configuration.table + '.userid, ' + configuration.table + '.oauth_token, ' + configuration.table + '.oauth_token_secret, ' + configuration.table + '.screen_name, ' + configuration.table + '.x_auth_expires, ' + configuration.table + '.access_token FROM oauth WHERE ?';
    db.get().query(sql, [fromDB], function(err, result) {
      console.log(JSON.stringify(result));
      if(callback !== undefined) {
        callback();
      } else {
        return;
      }
    }
  }
}

exports.storeCreds(credentials, callback){
  if(state.pool !== null){
    if(credentials.client_id !== undefined && credentials.user_id !== undefined) {
      var toDB = {};
      toDB.clientid = credentials.client_id;
      toDB.userid = credentials.user_id;
      if(credentials.access_token !== undefined) toDB.access_token = credentials.access_token;
      if(credentials.oauth_token !== undefined) toDB.oauth_token = credentials.oauth_token;
      if(credentials.oauth_token_secret !== undefined) toDB.oauth_token_secret = credentials.oauth_token_secret;
      if(credentials.screen_name !== undefined) toDB.screen_name = credentials.screen_name;
      if(credentials.x_auth_expires !== undefined) toDB.x_auth_expires = credentials.x_auth_expires;
    }
    db.get().query('INSERT INTO `' + configuration.table + '` SET ? ON DUPLICATE KEY UPDATE ?', [toDB, toDB], function(err, result) {
      if(callback !== undefined) callback();
    }
  }
}

exports.prepare = function(sql, arr){
  return mysql.format(sql, arr)
}
