// =============================================================================
// Module dependencies
// =============================================================================
var passport = require('passport-strategy');
var jwt = require('jsonwebtoken');
var util = require('util');

// =============================================================================
// Strategy constructor
// =============================================================================
function Strategy(options, verify) {

  if (typeof options != 'object') options = {};

  if (!options.secretOrPublicKey) throw new TypeError(
    'JwtCookieComboStrategy requires a secret or public key'
  );

  if (!verify) throw new TypeError(
    'JwtCookieComboStrategy requires a verify callback'
  );

  passport.Strategy.call(this);

  this.name = 'jwt-cookiecombo';
  this._verify = verify;

  this._jwtVerifyOptions = Object.assign({}, options.jwtVerifyOptions);
  this._passReqToCallback = options.passReqToCallback || false;
  this._jwtHeaderKey = options.jwtHeaderKey || 'authorization';
  this._jwtCookieName = options.jwtCookieName || 'jwt';
  this._secretOrPublicKey = options.secretOrPublicKey;

  this._jwtHeaderKey = this._jwtHeaderKey.toLowerCase();

}

// =============================================================================
// Inherit from passport.Strategy
// =============================================================================
util.inherits(Strategy, passport.Strategy);

// =============================================================================
// Authenticate request based on the payload of a json web token
// =============================================================================
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};

  var jwtString = null;

  if (req.signedCookies && this._jwtCookieName in req.signedCookies)
    jwtString = req.signedCookies[this._jwtCookieName];
  else if (req.headers && this._jwtHeaderKey in req.headers)
    jwtString = req.get(this._jwtHeaderKey);

  if (!jwtString) return this.fail({
    message: options.badRequestMessage || 'Missing token'
  }, 400);

  jwt.verify(jwtString, this._secretOrPublicKey,
    this._jwtVerifyOptions, (jwt_err, payload) => {

      if (jwt_err) return this.fail(jwt_err);

      var verified = (err, user, info) => {
        if (err) return this.error(err);
        if (!user) return this.fail(info);
        this.success(user, info);
      };

      try {
        if (this._passReqToCallback) this._verify(req, payload, verified);
        else this._verify(payload, verified);
      }
      catch (ex) {
        return this.error(ex);
      }
    });
};

// =============================================================================
// Expose Strategy
// =============================================================================
module.exports = Strategy;