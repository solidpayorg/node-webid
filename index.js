var request = require('request');
var url = require('url');
var $rdf = require('rdflib');
var SPARQL_QUERY = 'PREFIX cert: <http://www.w3.org/ns/auth/cert#> SELECT ?webid ?m ?e WHERE { ?webid cert:key ?key . ?key cert:modulus ?m . ?key cert:exponent ?e . }';

exports.VerificationAgent = VerificationAgent;
exports.get = get;
exports.verify = verify;

function VerificationAgent (certificate) {
  this.certificate = certificate || {};
};

VerificationAgent.prototype.getURIs = function () {
  var uris = [];
  if (this.certificate.subjectaltname) {
    this.certificate.subjectaltname.replace(/URI:([^, ]+)/g, function (match, uri) {
      return uris.push(uri);
    })
  }
  return uris;
};

VerificationAgent.prototype.verify = function (callback) {
  var that = this;

  // Collect URIs in certificate
  var uris = that.getURIs();

  // No uris
  if (uris.length === 0) {
    return callback('Empty Subject Alternative Name field in certificate');
  }

  // Get first URI
  var uri = uris.shift()
  get(uri, function(err, body, headers) {
    if (err) {
      return callback(err);
    }

    // Verify Key
    that.verifyKey(uri, body, headers, function(err, success) {
      if (err) {
        return callback(err);
      }
      callback(null, uri);
    })
  })
};

VerificationAgent.prototype.verifyKey = function (uri, profile, mimeType, callback) {
  var that = this;
  var graph = new $rdf.graph();
  var cert = $rdf.sym('http://www.w3.org/ns/auth/cert#key');
  var found = false;

  if (!that.certificate.modulus)
    return callback('Missing modulus value in client certificate');

  if  (!that.certificate.exponent) {
    return callback('Missing exponent value in client certificate');
  }

  parse(profile, graph, uri, mimeType, function (err) {
    if (err) {
      return callback(err);
    }

    var certExponent = parseInt(that.certificate.exponent, 16).toString();
    var query = $rdf.SPARQLToQuery(SPARQL_QUERY, undefined, graph);
    graph.query(
      query,
      function (result){
        if (found) {
          return;
        }
        var modulus = result['?m'].value;
        var exponent = result['?e'].value;

        if (modulus != null &&
           exponent != null &&
           (modulus.toLowerCase() === that.certificate.modulus.toLowerCase()) &&
           exponent === certExponent) {
          found = true;
        }
      },
      undefined, // testing
      function () {
        if (!found) {
          return callback('Certificate public key not found in the user\'s profile');
        }
        return callback(null, true);
      };
    )
  });
};

function parse (profile, graph, uri, mimeType, callback) {
  try {
    $rdf.parse(profile, graph, uri, mimeType);
    return callback(null, graph);
  } catch(e) {
    return callback('Cound not load/parse profile data');
  }
};

function verify (certificate, callback) {
  var agent = new VerificationAgent(certificate);
  return agent.verify(callback);
};

function get (uri, callback) {
  var parsedURI = url.parse(uri);
  var options = {
    url: parsedURI,
    method: 'GET',
    headers: {
      'Accept': 'text/turtle, application/ld+json'
    }
  };

  request(options, function (err, res, body) {
    if (err) {
      return callback('Error fetch profile from '+parsedURI+': '+err);
    }
    if (res.statusCode != 200) {
      return callback('Failed to retrieve WebID from '+parsedURI+': HTTP '+res.statusCode);
    }
    callback(null, body, res.headers['content-type']);
  })
};
