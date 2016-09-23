'use strict';

var forge = require('node-forge');
var BigInteger = forge.jsbn.BigInteger;
var bigInt = require("big-integer");

const EventEmitter = require('events');
const util = require('util');



// pithanoi prime 30k+i for i = 1, 7, 11, 13, 17, 19, 23, 29
var GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2];
var THIRTY = new BigInteger(null);
var bits = 128;
var exponent = "67849492012064603525502413864581601255843190582896059031333969517102908698009";
var modulus = "2488305068742644273557582289228577695008613947504239231451478997448862967615054559158646690894413368612518781574622331108225213890389508634163395377693";
THIRTY.fromInt(30);

// generate random BigInteger
var num = generateRandom(bits);
var PrivatePrimeNumber = '';
var PublicPrimeNumber = '';
var DHKeyExchange = '';
var ServerCookie = '';

module.exports = RandomGenerators;

function RandomGenerators() {
    EventEmitter.call(this);
    this.seed = 34;
    GenerateCookie();
    PrivatePrimeNumber = findPrivatePrime(num, function(num) {
        return num.toString();
    });
    PublicPrimeNumber = findPublicPrime(PrivatePrimeNumber);
}
util.inherits(RandomGenerators, EventEmitter);
RandomGenerators.prototype.__proto__ = EventEmitter.prototype;

RandomGenerators.prototype.PrimeNumber = function() {
    return PrivatePrimeNumber;
}

RandomGenerators.prototype.PublicPrimeNumber = function() {
    return PublicPrimeNumber;
}

RandomGenerators.prototype.CookieServer = function(qty) {
    return ServerCookie;
}

function GenerateCookie() {
    var bytes = forge.random.getBytesSync(32);
    ServerCookie = forge.util.bytesToHex(bytes)
        // console.log(ServerCookie);
}

function generateRandom(bits) {
    var rng = {
        nextBytes: function(x) {
            var b = forge.random.getBytes(x.length);
            for (var i = 0; i < x.length; ++i) {
                x[i] = b.charCodeAt(i);
            }
        }
    };
    var num = new BigInteger(bits, rng);

    // force MSB set
    var bits1 = bits - 1;
    if (!num.testBit(bits1)) {
        var op_or = function(x, y) {
            return x | y;
        };
        num.bitwiseTo(BigInteger.ONE.shiftLeft(bits1), op_or, num);
    }

    num.dAddOffset(31 - num.mod(THIRTY).byteValue(), 0);

    return num;
}


RandomGenerators.prototype.SessionGenerator = function(ClientResult) {
    DHKeyExchange = bigInt(ClientResult).
    modPow(PrivatePrimeNumber, modulus).toString();
}

RandomGenerators.prototype.DHKeyExchange = function() {
    return DHKeyExchange;
}

RandomGenerators.prototype.pseudorandom = function() {
    this.seed++;
    var x = Math.sin(this.seed) * 0.5;
    return x;
}

function findPrivatePrime(num, callback) {
    var deltaIdx = 0;


    var start = Date.now();
    while (Date.now() - start < 100) {

        if (num.isProbablePrime(2)) {
            return callback(num);
        }

        num.dAddOffset(GCD_30_DELTA[deltaIdx++ % 8], 0);
    }


    setTimeout(function() {
        findPrivatePrime(num, callback);
    });

}

function findPublicPrime(ServerPrivate) {
    return bigInt(exponent).
    modPow(ServerPrivate, modulus).toString();
}