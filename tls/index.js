exports.verify = verify
exports.verifyKey = verifyKey
exports.generate = generate

var $rdf = require('rdflib')
var get = require('../lib/get')
var parse = require('../lib/parse')
var pem = require('pem')
var Graph = $rdf.graph
var SPARQL_QUERY = 'PREFIX cert: <http://www.w3.org/ns/auth/cert#> SELECT ?webid ?m ?e WHERE { ?webid cert:key ?key . ?key cert:modulus ?m . ?key cert:exponent ?e . }'

function verify (certificate, callback) {

  if (!certificate) {
    return callback(new Error('No certificate given'))
  }

  // Collect URIs in certificate
  var uris = getUris(certificate)

  // No uris
  if (uris.length === 0) {
    return callback(new Error('Empty Subject Alternative Name field in certificate'))
  }

  // Get first URI
  var uri = uris.shift()
  get(uri, function (err, body, headers) {
    if (err) {
      return callback(err)
    }

    // Verify Key
    verifyKey(certificate, uri, body, headers, function (err, success) {
      return callback(err, uri)
    })
  })
}

function getUris (certificate) {
  var uris = []

  if (certificate && certificate.subjectaltname) {
    certificate
      .subjectaltname
      .replace(/URI:([^, ]+)/g, function (match, uri) {
        return uris.push(uri)
      })
  }
  return uris
}

function verifyKey (certificate, uri, profile, mimeType, callback) {
  var graph = new Graph()
  var found = false

  if (!certificate.modulus) {
    return callback(new Error('Missing modulus value in client certificate'))
  }

  if (!certificate.exponent) {
    return callback(new Error('Missing exponent value in client certificate'))
  }

  parse(profile, graph, uri, mimeType, function (err) {
    if (err) {
      return callback(err)
    }
    console
    var certExponent = parseInt(certificate.exponent, 16).toString()
    var query = $rdf.SPARQLToQuery(SPARQL_QUERY, undefined, graph)
    graph.query(
      query,
      function (result) {
        if (found) {
          return
        }
        var modulus = result['?m'].value
        var exponent = result['?e'].value

        if (modulus != null &&
           exponent != null &&
           (modulus.toLowerCase() === certificate.modulus.toLowerCase()) &&
           exponent === certExponent) {
          found = true
        }
      },
      undefined, // testing
      function () {
        if (!found) {
          return callback(new Error('Certificate public key not found in the user\'s profile'))
        }
        return callback(null, true)
      }
    )
  })
}

/*
Generate a webid cert.
options should have the uri of the profile in it.

callback(err, certificate)
*/
function generate(options, callback) {
    if (!options.uri) {
        return callback(new Error('No profile uri found'))
    }

    // Maybe we need to validate the uri first?

    // If we are here then the options has the uri
    // prepare the options for csr
    var csr_options = {
        clientKey: options.clientKey, // We need the clients pub key for this, <keygen>?
        keyBitSize: options.keySize || 2048,
        altNames: [
            'URI: ' + options.uri
        ],
        selfSigned: true // Self sign for now
    }

    var csr = pem.createCSR(csr_options, function (err, csr) {
        if (err) {
            console.log('Error: ' + err.message)
            throw err
        }
        return csr
    })

    var cert_options = {
        csr: this.csr,
        days: 999
    }

    var cert = pem.createCertificate(cert_options, function (err, result) {
        if (err) {
            console.log('Error: ' + err.message)
            throw err
        }
        console.log(result)
        return result.certificate
    })

    // Verify the cert once it's created
    // verify(cert, function (err, result) {
    //     if (err) {
    //         console.log('Error: ' + err.message)
    //         throw err
    //     }
    //     // Do something with result
    // })

}
