//var raptor = require('./raptor.js');
var url = require('url');
var http = require('http');
var request = require('request');
var _ = require('underscore')._;
var querystring = require('querystring');

var rdfstore = require('./rdfstore.js');

var Foaf = function (graph) {
    this.graph = graph;
}
Foaf.prototype.parse = function () {
    return {
            title: "WebID Sucess !",
            name: this._getValue('name'),
            birthday: this._getValue('birthday'),
            webid: this._getWebid(),
            knows: this._getKnows()
        };
}
/**
 * Gets the WebID (URI).
 */
Foaf.prototype._getWebid = function() {
    var temp = this.graph.filter(function(t){ return t.predicate.equals("http://www.w3.org/ns/auth/cert#key") }).toArray();
    if (temp.length == 1) {
        return temp[0].subject.valueOf();
    }
    else {
        return "";
    }
}
/**
 * Get knows relation 
 * @return List of "known" WebID.
 */
Foaf.prototype._getKnows = function () { 
    var temp = this.graph.filter(function(t){ return t.predicate.equals("http://xmlns.com/foaf/0.1/knows") }).toArray();
    var result = [];
    _.each(temp, function (elem) {
        result.push(elem.object.valueOf());
    });
    return result;
}
/**
 * @param The FOAF value to get
 */
Foaf.prototype._getValue = function (value) {
    var temp = this.graph.filter(function(t){ return t.predicate.equals("http://xmlns.com/foaf/0.1/" + value) }).toArray();
    if (temp.length == 1) {
        return temp[0].object.valueOf();
    }
    //TODO: cover the case when 
    else {
        return "";
    }
}
/**
 *
 */
var VerificationAgent = function (certificate) {
    this.subjectAltName = certificate.subjectaltname;
    this.modulus = certificate.modulus;
    this.exponent = parseInt(certificate.exponent,16).toString(); // Convert to hex
    this.uris = this.subjectAltName.split(",");
    for (var i = 0; i < this.uris.length; i++) {
        this.uris[i] = this.uris[i].split("URI:")[1];
    }
};
/**
 *
 */
VerificationAgent.prototype.verify = function (callback) {
    this._verify(this.uris, callback);
};
/**
 * 
 */
VerificationAgent.prototype._verify = function (uris, callback) {
    if (uris.length === 0) {
        callback(false,"certificateProvidedSAN");
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
/**
 * Cleans input to authorize only Hexadecimal 
 */
VerificationAgent.prototype._clean = function (input, pattern) {
    var match = input.match(/[0-9A-Fa-f]+/);
    if (match == null) {
        return null;
    }
    else {
        return match[0].toUpperCase();
    }
}

VerificationAgent.prototype._verifyWebId = function (webidUri, data, mediaTypeHeader, callback) {
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
                                        modulus = that._clean(results[i].m.value);
                                        exponent = that._clean(results[i].e.value);
                                    }
                                }
                                if (modulus != null && exponent != null) {
                                    // Check if the modulus and exponent are equals
                                    if ((modulus == that.modulus) && (exponent == that.exponent)) {
                                        // Every thing is OK, webid valid
                                        // Transform store to graph
                                        store.node(webidUri, function(success, graph) {
                                            callback(true,graph);
                                        });
                                    }
                                    else {
                                        // The certificate does not identity this FOAF file
                                        callback(false, "falseWebID")
                                    }
                                } else {
                                    callback(false,"profileAllKeysWellFormed");
                                }
                            } else {
                                callback(false,"profileAllKeysWellFormed");
                            }
                        });
                    }
                    else {
                        // Can't load 
                        callback(false,"profileWellFormed");
                    }
                });
            });
        }
        else {
            // Can't download profile
            callback(false,"profileGet");
        }
    });
};

exports.VerificationAgent = VerificationAgent;
exports.Foaf = Foaf;