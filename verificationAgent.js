var request = require('request')
var url = require('url')
var rdfstore = require('rdfstore')
var PREFIX_SPARQL = 'PREFIX cert: <http://www.w3.org/ns/auth/cert#> SELECT ?webid ?m ?e WHERE { ?webid cert:key ?key . ?key cert:modulus ?m . ?key cert:exponent ?e . }'

module.exports = VerificationAgent

function VerificationAgent (certificate) {
  if (!certificate) {
    throw new Error("missing certificate for WebID verification agent")
  }
  this.uris = []
  this.subjectAltName = certificate.subjectaltname
  this.modulus = certificate.modulus
  this.exponent = parseInt(certificate.exponent, 16).toString() // convert to hex

  this.subjectAltName.replace(/URI:([^, ]+)/g, function (match, uri) {
    return this.uris.push(uri);
  })
}

VerificationAgent.prototype.verify = function (err, callback) {
  if (this.uris.length === 0) {
    return callback('certificateProvidedSAN')
  }

  var uri = this.uris.shift()
  this.getWebID(uri, callback)
}

VerificationAgent.prototype.getWebID = function (uri, callback) {
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
    this.verifyWebID(uri, body, res.headers['content-type'], callback)
  })
}

VerificationAgent.prototype.verifyWebID = function(webID, profile, mimeType, callback) {
  rdfstore.create(function (store) {
    store.load(mimeType, profile, function(loaded) {
      if (!loaded) {
        return callback("profileWellFormed");
      }

      store.execute(PREFIX_SPARQL, function(success, results) {
        if (!success) {
          return callback("profileAllKeysWellFormed");
        }
        var i = 0
        while (i < results.length) {
          var modulus = results[i].m.value
          var exponent = results[i].e.value
          if (modulus != null &&
              exponent != null &&
              (modulus.toLowerCase() === this.modulus.toLowerCase()) &&
              exponent === this.exponent) {
            return callback(null, webID)
          }
          i++
        }
        return callback("profileAllKeysWellFormed");
      })
    })
  })
}

