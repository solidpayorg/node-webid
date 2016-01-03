exports.verify = verify
exports.verifyKey = verifyKey
exports.generate = generate

var $rdf = require('rdflib')
var get = require('../lib/get')
var parse = require('../lib/parse')
var forge = require('forge')
var pki = forge.pki
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

Rewriting to use node-forge.

callback(err, certificate)
*/
function generate(options, callback) {
    if (!options.uri) {
        return callback(new Error('No profile uri found'))
    }

	/* options:
	 * cn: common name info for the cert
	 * clientkey: the clients public key
	 * subjectAltName: subject alternative name, this should have the clients webid as the first element
	 * keystrength: integer
	 */
	// Generate an X.509 client cert
	//var keys = pki.rsa.generateKeyPair(options.keyStrength || 2048)
	var cert = pki.createCertificate()

	//cert.publicKey = keys.publicKey
	//The public key should come from the client
	cert.publicKey = options.clientKey
	//The validity of the cert
	cert.validity.notBefore = new Date();
	cert.validity.notAfter = new Date();
	cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

    var attrs = [{
        name: 'commonName',
        value: options.commonName
    }, {
        name: 'countryName',
        value: options.countryName || 'not specified'
    }, {
        name: 'localityName',
        value: 'Blacksburg'
    }, {
        name: 'organizationName',
        value: 'Test'
    }]

    cert.setSubject(attrs)
    cert.setIssuer(attrs)
    // Set the cert extensions
    cert.setExtensions([{
        name: 'subjectAltName',
        altNames: [{
            type: 6, // URI
            value: 'http://example.org/webid#me'
        }]
    }])

    // Should we self-sign the cert? For now I suppose.
    cert.sign(options.clientKey)
}
