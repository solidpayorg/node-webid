//var raptor = require('./raptor.js');
var url = require('url');
var http = require('http');
var request = require('request');
var querystring = require('querystring');

var rdfstore = require('./rdfstore.js');

exports.VerificationAgent = function (certificate) {
    console.log("Got certificate alt name" + this.subjectAltName);
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
        throw new VerificationAgentError("certificateProvidedSAN");
    } else {
        var that = this;
        var parsedUrl = url.format(uris[0]);
        var options = {
            url: parsedUrl,
            method: 'GET',
            headers: {
                "Accept": "application/rdf+xml,application/xhtml+xml,text/html"
            }
        }; 
        
        console.log("Downloading FOAF file from: " + parsedUrl);
        var rq = request(options, function (error, response, body) {
            if (!error) {
                that._verifyWebId(parsedUrl, body, response.headers['content-type'], callback);
            }
            else {
                uris.shift();
                that._verify(uris, callback);
            }
        });
    }
};
exports.VerificationAgent.prototype._clean = function (input, pattern) {
    var match = input.match(pattern);
    if (match == null) {
        return null;
    }
    else {
        return match[0];
    }
}

exports.VerificationAgent.prototype._cleanModulus = function (modulus) {
    var that = this;
    return that._clean(modulus,/[0-9A-Fa-f]+/);
}

exports.VerificationAgent.prototype._cleanExponent = function (exponent) {
    var that = this;
    return that._clean(exponent,/[0-9]+/);
}

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
		if (!error) {
            rdfstore.create(function (store) {
                store.load("text/turtle", body, function (success, results) {
                    if (success) {
                        store.execute("PREFIX cert: <http://www.w3.org/ns/auth/cert#>\
                                       SELECT ?webid ?m ?e\
                                       WHERE {\
                                         ?webid cert:key ?key .\
                                         ?key cert:modulus ?m .\
                                         ?key cert:exponent ?e .\
                                       }", function (success, results) {
                            if (success) {
                                var modulus = null;
                                var exponent = null;
                                for (var i = 0; i < results.length; i++) {
                                    if (results[i].webid && results[i].webid.value === webidUri) {
                                        modulus = that._cleanModulus(results[i].m.value);
                                        exponent = that._cleanExponent(results[i].e.value);
                                    }
                                }
                                if (modulus != null && exponent != null) {
                                    console.log("Data ok");
                                } else {
                                    throw new VerificationAgentError("profileAllKeysWellFormed");
                                }
                            } else {
                                throw new VerificationAgentError("profileAllKeysWellFormed");
                            }
                        });
                    }
                    else {
                        // Can't load 
                        throw new VerificationAgentError("profileWellFormed");
                    }
                });
            });
        }
        else {
            // Can't download profile
            throw new VerificationAgentError("profileGet");
        }
    });
};

exports.VerificationAgentError = function (name, message) {  
    this.name = name || "Error during WebID validation";
    this.message = message || "";  
}  
exports.VerificationAgentError.prototype = new Error();  
exports.VerificationAgentError.prototype.constructor = exports.VerificationAgentError;  