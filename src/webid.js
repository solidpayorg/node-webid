//var raptor = require('./raptor.js');
var url = require('url');
var http = require('http');
var request = require('request');
var querystring = require('querystring');

var rdfstore = require('./rdfstore.js');

exports.VerificationAgent = function (certificate) {
    this.subjectAltName = certificate.subjectaltname;
    this.modulus = certificate.modulus;
    this.exponent = certificate.exponent;
    this.uris = this.subjectAltName.split(",");
    for (var i = 0; i < this.uris.length; i++) {
        this.uris[i] = this.uris[i].split("URI:")[1];
    }
};

exports.VerificationAgent.prototype.verify = function (callback) {
    this._verify(this.uris, callback);
};
/**
 * 
 */
exports.VerificationAgent.prototype._verify = function (uris, callback) {
    if (uris.length === 0) {
        callback(true, "Not ok");
    } else {
        var that = this;
        var parsedUrl = url.parse(uris[0]);
        var options = {
            url: parsedUrl,
            method: 'GET',
            headers: {
                "Accept": "application/rdf+xml,application/xhtml+xml,text/html"
            }
        }; 
        

        var rq = request(options, function (error, response, body) {
            if (!error) {
                that._verifyWebId(uris[0], body, response.headers['content-type'], callback);
            }
            else {
                uris.shift();
                that._verify(uris, callback);
            }
        });
    }
};
exports.VerificationAgent.prototype._verifyWebId = function (webidUri, data, mediaTypeHeader, callback) {
    var that = this;
    var mediaType = null;
    if (mediaTypeHeader === "application/rdf+xml") {
        mediaType = 'rdfxml';
    } else {
        mediaType = 'rdfa';
    }

    var options = {
        url: "http://semola-rdf.appspot.com/converter",
        method: 'POST',
        headers: {
            'content-type' : 'application/x-www-form-urlencoded'
        },
        body: querystring.stringify({input: data, inputType: "RDF/XML", outputType: "N-TRIPLE"})
    }; 

    // Converting RDF/XML to Turtle
    // Using my web service : http://semola-rdf.appspot.com/
    var rq = request(options, function (error, response, body) {
        //TODO : check errors
        rdfstore.create(function (store) {
            store.load("text/turtle", body, function (success, results) {
                store.execute("PREFIX cert: <http://www.w3.org/ns/auth/cert#>\
                               SELECT ?webid ?m ?e\
                               WHERE {\
                                 ?webid cert:key ?key .\
                                 ?key cert:modulus ?m .\
                                 ?key cert:exponent ?e .\
                               }", function (success, results) {
                    if (success) {
                        console.log(results);
                        var modulus = null;
                        var exponent = null;
                        for (var i = 0; i < results.length; i++) {
                            if (results[i].webid && results[i].webid.value === webidUri) {
                                modulus = results[i].m;
                                exponent = results[i].e;
                            }
                        }
                        if (modulus != null && exponent != null) {
                            console.log(modulus);
                            console.log(exponent);
                        } else {
                            callback(true, "certficateDataNotFound");
                        }
                    } else {
                        callback(true, "certficateDataNotFound");
                    }
                });
            });
        });

    });
};

exports.VerificationError = {
    certificateProvidedSAN: 0
};