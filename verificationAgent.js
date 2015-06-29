var request = require('request')
var url = require('url')
var rdfstore = require('rdfstore')
var PREFIX_SPARQL = 'PREFIX cert: <http://www.w3.org/ns/auth/cert#> SELECT ?webid ?m ?e WHERE { ?webid cert:key ?key . ?key cert:modulus ?m . ?key cert:exponent ?e . }'

module.exports = VerificationAgent

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
  var that = this

  console.log("req", options)
  request(options, function (err, res, body) {
    console.log('preq')
    if (err) {
      return callback('profileGet')
    }
    that.verifyWebID(uri, body, res.headers['content-type'], callback)
  })
}

VerificationAgent.prototype.verifyWebID = function(webID, profile, mimeType, callback) {

  var that = this
  rdfstore.create(function (err, store) {
    console.log('rdfstore', err, store)
    if (err) {
      return callback('internalError')
    }

    store.load(mimeType, profile, function(err, loaded) {
      if (err) {
        return callback('internalError')
      }
      if (loaded) {
        return callback('profileWellFormed');
      }
      console.log(mimeType, profile)
      console.log('loaded', loaded, store)
      store.execute(PREFIX_SPARQL, function(err, results) {
        console.log("the results", results)
        // console.log(results, webID, profile)
        if (err) {
          return callback('profileAllKeysWellFormed');
        }
        var i = 0
        while (i < results.length) {
          var modulus = results[i].m.value
          var exponent = results[i].e.value
          if (modulus != null &&
              exponent != null &&
              (modulus.toLowerCase() === that.modulus.toLowerCase()) &&
              exponent === that.exponent) {
            return callback(null, webID)
          }
          i++
        }
        return callback('profileAllKeysWellFormed');
      })
    })
  })
}

