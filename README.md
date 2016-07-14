# passport-jwt-cookiecombo

[Passport](http://passportjs.org/) strategy for lightning-fast authenticating 
with a [JSON Web Token](http://jwt.io), based on the [JsonWebToken implementation 
for node.js](https://github.com/auth0/node-jsonwebtoken).

JWT Cookie Combo Strategy for Passport combines the authorization header for 
native app requests and a more secure secured, http-only, same site, signed and 
stateless cookie for web requests from a browser.

The best: Every single request saves both techniques a database query, because 
the user comes from the token. You just use `req.user` in your actions.

## Install

    npm install passport-jwt-cookiecombo

## TL;DR

```javascript
// =============================================================================
// Configure Strategy
// =============================================================================
var JwtCookieComboStrategy = require('passport-jwt-cookiecombo');

passport.use(new JwtCookieComboStrategy({
    secretOrPublicKey: 'StRoNGs3crE7'
}, (payload, done) => {
    return done(null, payload.user);
}));
```

```javascript
// =============================================================================
// Sign Token
// =============================================================================
var jwt = require('jsonwebtoken');

router.post('/login', passport.authenticate('local'), (req, res) => {
    jwt.sign({ user: req.user }, 'StRoNGs3crE7', (err, token) => {
        if (err) return res.json(err);

        // Send Set-Cookie header
        res.cookie('jwt', token, {
            httpOnly: true,
            sameSite: true,
            signed: true,
            secure: true
        });
        
        // Return json web token
        return res.json({
            jwt: token
        });
    });
});
```

```javascript
// =============================================================================
// Authenticate Requests
// =============================================================================
var express = require('express');

app.use('/api/v1', passport.authenticate('jwt-cookiecombo', {
    session: false
}), (req, res, next) => {
    return next();
});
```

## Usage

### Sample Login with Set-Cookie

```javascript
// =============================================================================
// Dependencies
// =============================================================================
var cookieParser = require('cookie-parser');
var passport = require('passport');
var jwt = require('jsonwebtoken');
var express = require('express');
```
```javascript
// =============================================================================
// Express App inits cookie with a secret
// =============================================================================
var app = express();

// Pass a secret to sign the secured http cookie
app.use(cookieParser(config.jwt.secret));
```

```javascript
// =============================================================================
// Login route with any Passport authentication strategy
// =============================================================================
// Passport provides us the authenticated user in the request
router.post('/login', passport.authenticate('local', {
    session: false
}), (req, res) => {
    // Create and sign json web token with the user as payload
    jwt.sign({
        user: req.user
    }, config.jwt.secret, config.jwt.options, (err, token) => {
        if (err) return res.status(500).json(err);

        // Send the Set-Cookie header with the jwt to the client
        res.cookie('jwt', token, config.jwt.cookie);

        // Response json with the jwt
        return res.json({
            jwt: token
        });
    });
});
```

```javascript
// =============================================================================
// Sample Passport Authentication where the user is set for the jwt payload
// =============================================================================
passport.use(new LocalStrategy({
    // My users have only email
    usernameField: 'email',
    session: false
}, (username, password, done) => {
    User.findOne({
        email: username
    })
    // Explicitly select the password when the model hides it
    .select('password role').exec((err, user) => {
        if (err) return done(err);
        
        // Copy the user w/o the password into a new object
        if (user && user.verifyPassword(password)) return done(null, {
            id: user._id,
            role: user.role
        });

        return done(null, false);
    });
}));
```

### JWT Cookie Combo Passport Strategy

```javascript
var JwtCookieComboStrategy = require('passport-jwt-cookiecombo');

// Authenticate API calls with the Cookie Combo Strategy
passport.use(new JwtCookieComboStrategy({
    secretOrPublicKey: config.jwt.secret,
    jwtVerifyOptions: config.jwt.options,
    passReqToCallback: false
}, (payload, done) => {
    return done(null, payload.user, {});
}));
```
The following possible options for a JsonWebToken will be directly passed on to [jsonwebtoken.verify](https://github.com/auth0/node-jsonwebtoken/blob/master/README.md#jwtverifytoken-secretorpublickey-options-callback).


`secretOrPublicKey:` is a string or buffer containing either the secret for HMAC algorithms, or the PEM
encoded public key for RSA and ECDSA.

`jwtVerifyOptions: {`

* `algorithms`: List of strings with the names of the allowed algorithms. For instance, `["HS256", "HS384"]`. Default: `HS256`.
* `audience`: if you want to check audience (`aud`), provide a value here
* `issuer` (optional): string or array of strings of valid values for the `iss` field.
* `ignoreExpiration`: if `true` do not validate the expiration of the token.
* `ignoreNotBefore`...
* `subject`: if you want to check subject (`sub`), provide a value here
* `clockTolerance`: number of second to tolerate when checking the `nbf` and `exp` claims, to deal with small clock differences among different servers

`}`

### JWT Cookie Combo global API routes protection

```javascript
app.use('/api/v1', passport.authenticate('jwt-cookiecombo', {
    session: false
}), (req, res, next) => {
    return next();
});
```

### Sample Config

```javascript
module.exports = {
    jwt: {
        secret: process.env.JWT_SECRET || 'SetStrongSecretInDotEnv',
        options: {
            audience: 'https://example.io',
            expiresIn: '12h', // 1d
            issuer: 'example.io'
        },
        cookie: {
            httpOnly: true,
            sameSite: true,
            signed: true,
            secure: true
        }
    }
};
```
### Sample Auth-Header
Key | Token
--- | ---
Authorization | eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNTc5ZWVkZGRlMDEzNz...

### Sample Token
##### HEADER: ALGORITHM & TOKEN TYPE
```javascript
{
    "alg": "HS256",
    "typ": "JWT"
}
```

##### PAYLOAD: DATA
```javascript
{
    "user": {
        "id": "577839eeddde013794ae2332",
        "role": "admin"
    },
    "iat": 1468340405,
    "exp": 1468383605,
    "aud": "https://example.io",
    "iss": "example.io"
}
```

##### VERIFY SIGNATURE
```javascript
HMACSHA256 (
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```
## Tonic Notebook
Try it out on tonic.dev [tonic + npm: passport-jwt-cookiecombo](https://tonicdev.com/codebarista/passport-jwt-cookiecombo)

## License

[ISC](https://git.io/vKR49)
