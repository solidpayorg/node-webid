var request = require('request')
var url = require('url')
var $rdf = require('rdflib')
var PREFIX_SPARQL = 'PREFIX cert: <http://www.w3.org/ns/auth/cert#> SELECT ?webid ?m ?e WHERE { ?webid cert:key ?key . ?key cert:modulus ?m . ?key cert:exponent ?e . }'

exports.VerificationAgent = VerificationAgent
exports.get = get
exports.verify = verify

function VerificationAgent (certificate) {
  if (!certificate) {
    throw new Error('missing certificate for WebID verification agent')
  }

  this.uris = []
  this.subjectAltName = certificate.subjectaltname
  this.modulus = certificate.modulus
  this.exponent = parseInt(certificate.exponent, 16).toString() // hex

  var that = this
  this.subjectAltName.replace(/URI:([^, ]+)/g, function (match, uri) {
    return that.uris.push(uri);
  })
}

VerificationAgent.prototype.verify = function (callback) {
  if (this.uris.length === 0) {
    return callback('certificateProvidedSAN')
  }

  var uri = this.uris.shift()
  var that = this
  get(uri, function(err, body, headers) {
    if (err) {
      return callback(err)
    }

    that.verifyKey(uri, body, headers, function(err, success) {
      if (err) {
        return callback(err)
      }
      callback(null, uri)
    })
  })
}

function parse (profile, graph, uri, mimeType, callback) {
  try {
    $rdf.parse(profile, graph, uri, mimeType)
    return callback(null, graph)
  } catch(e) {
    return callback('loadStore')
  }
}

VerificationAgent.prototype.verifyKey = function (uri, profile, mimeType, callback) {
  var graph = new $rdf.graph()
  var cert = $rdf.sym('http://www.w3.org/ns/auth/cert#key')
  var found = false
  var that = this

  parse(profile, graph, uri, mimeType, function (err) {
    if (err) {
      return callback(err)
    }

    var query = $rdf.SPARQLToQuery(PREFIX_SPARQL, undefined, graph)
    graph.query(
      query,
      function (result){
        if (found) {
          return
        }
        var modulus = result['?m'].value
        var exponent = result['?e'].value
        if (modulus != null &&
           exponent != null &&
           (modulus.toLowerCase() === that.modulus.toLowerCase()) &&
           exponent === that.exponent) {
          found = true
        }
      },
      undefined, // testing
      function () {
        if (!found) {
          return callback('profileAllKeysWellFormed')
        }
        return callback(null, true)
      }
    )
  })
}

function verify (certificate, callback) {
  var agent = new VerificationAgent(certificate)
  return agent.verify(callback)
}

function get (uri, callback) {
  var parsedURI = url.parse(uri)
  var options = {
    url: parsedURI,
    method: 'GET',
    headers: {
      'Accept': 'text/turtle, application/ld+json'
    }
  }

  request(options, function (err, res, body) {
    if (err) {
      return callback('profileGet')
    }
    if (res.statusCode != 200) {
      return callback('failedToRetrieveWebID')
    }
    callback(null, body, res.headers['content-type'])
  })
}

