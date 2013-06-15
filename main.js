define(['querystring'],
function(qs) {

  /**
   * `Provider` constructor.
   *
   * @param {Object} opts
   * @api public
   */
  function Provider(opts) {
    opts = opts || {};
    this._authorizationURL = opts.authorizationURL;
    this._clientID = opts.clientID;
    this._redirectURL = opts.redirectURL || opts.callbackURL;
    this._scope = opts.scope;
    this._responseType = opts.responseType || 'code';
  }
  
  Provider.prototype.login = function() {
    console.log('OAuth2Provider.login');
    
    var query = qs.stringify({ client_id: this._clientID,
                               redirect_uri: this._redirectURL,
                               scope: this._scope,
                               response_type: this._responseType })
      , url = this._authorizationURL + '?' + query;
    
    this.redirect(url);
  }
  
  Provider.prototype.validate = function(location, cb) {
    console.log('OAuth2Provider.validate');
    
    var resp;
    switch (this._responseType) {
    case 'code':
      resp = location.search.slice(1); // omit the leading `?`
      break;
    case 'token':
      resp = location.hash.slice(1); // omit the leading `#`
    }
    
    var self = this
      , params = qs.parse(resp)
      , creds = { accessToken: params.access_token,
                  expiresIn: params.expires_in,
                  type: params.token_type || 'bearer' }
    
    if (params.access_token) {
      validateToken(params.access_token, function(err, extra) {
        if (err) { return cb(err); }
        
        function fetched(err, profile) {
          if (err) { return cb(err); }
          return cb(null, profile, creds);
        }
        
        var arity = self.userProfile.length;
        if (arity == 3) {
          self.userProfile(params.access_token, extra, fetched);
        } else {
          self.userProfile(params.access_token, fetched);
        }
      });
    }
    
    // Validate the token by ensuring that it was issued to the expected
    // application (aka client).  Any token received that was not issued to the
    // expected application is suggestive of a malicious request.
    //
    // For more details on this topic, refer to:
    //   [The problem with OAuth for Authentication.](http://www.thread-safe.com/2012/01/problem-with-oauth-for-authentication.html)
    //   [Solutions for using OAuth 2.0 for Authentication](http://www.thread-safe.com/2012/01/solutions-for-using-oauth-20-for.html)
    //   [More on OAuth implicit flow application vulnerabilities.](http://www.thread-safe.com/2012/02/more-on-oauth-implicit-flow-application.html)
    function validateToken(token, done) {
      self.tokenInfo(token, function(err, info, extra) {
        if (err) { return done(err); }
        if (info.audience !== self._clientID) {
          return done(new Error('OAuth 2.0 token not intended for client.'));
        }
        return done(null, extra);
      });
    }
  }
  
  Provider.prototype.tokenInfo = function(token, cb) {
    return cb(new Error('Failed to fetch token info. Not implemented.'));
  }
  
  Provider.prototype.userProfile = function(token, cb) {
    return cb(null, {});
  }
  
  
  return Provider;
});
