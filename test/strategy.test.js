// =============================================================================
// Dependencies
// =============================================================================
var chai = require('chai');
var expect = chai.expect;

chai.use(require('chai-passport-strategy'));

// =============================================================================
// Package test
// =============================================================================
describe('passport-jwt-cookiecombo', () => {

    var strategy = require('..');

    it('should export Strategy constructor directly from package', () => {
        expect(strategy).to.be.a('function');
        expect(strategy).to.equal(strategy.Strategy);
    });

});

// =============================================================================
// Constructor tests
// =============================================================================
var Strategy = require('../lib/strategy');

describe('Strategy', () => {

    var strategy = new Strategy({
        secretOrPublicKey: 'StRoNGs3crE7'
    }, () => {});

    it('should be named jwt-cookiecombo', () => {
        expect(strategy.name).to.equal('jwt-cookiecombo');
    });

    it('should throw if constructed without secretOrPublicKey option', () => {
        expect(() => {
            var s = new Strategy();
        }).to.throw(TypeError, 'JwtCookieComboStrategy requires a secret or public key');
    });

    it('should throw if constructed without a verify callback', () => {
        expect(() => {
            var s = new Strategy({
                secretOrPublicKey: 'StRoNGs3crE7'
            });
        }).to.throw(TypeError, 'JwtCookieComboStrategy requires a verify callback');
    });

});