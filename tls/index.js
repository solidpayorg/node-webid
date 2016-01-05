exports.verify = verify
exports.verifyKey = verifyKey
exports.generate = generate

var $rdf = require('rdflib')
var get = require('../lib/get')
var parse = require('../lib/parse')
var forge = require('node-forge')
var certificate = require('crypto').Certificate
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

@param options The options object { spakc: clientkey, agent: uri }
@param callback The callback to be executed expects args: Error err, Cert certfificate

@return callback

The callback arg cert should be an object reprsentation of the certificate with
the psk12 format of the certificate.
*/
function generate(options, callback) {
    if (!options.uri) return callback(new Error('No uri found'), null)
    else if (!options.spkac return callback(new Error('No public key found'), null)

    /*
    These can be expanded later, but this is the smallest amount of info needed.
    options = {
        spakc: the public key from the client
        agent: a unique uri to be used as the subject alt name
    }

    // Usage example
    webid('tls').generate({
+          spkac: req.body['spkac'],
+          agent: agent // TODO generate agent
+        }, callback)
    */

	var cert = pki.createCertificate()
    var spkac = parseSpkac(options.spkac)

    cert.publicKey = spkac.publicKey
	cert.validity.notBefore = new Date()
	cert.validity.notAfter = new Date()
	cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

    var attrs = [{
        name: 'commonName',
        value: options.commonName || options.uri
    }, {
        name: 'countryName',
        value: options.countryName || ' '
    }, {
        name: 'localityName',
        value: options.localityName || ' '
    }, {
        name: 'organizationName',
        value: options.organizationName || ' '
    }]

    cert.setSubject(attrs)
    cert.setIssuer(attrs)
    // Set the cert extensions
    cert.setExtensions([{
        name: 'subjectAltName',
        altNames: [{
            type: 6, // URI
            value: options.agent
        }]
    }])

    // Should we self-sign the cert? For now I suppose.
    cert.sign(cert.publicKey)

    // Now we need to verify the certificate
    verify(pem, function (err, result) {
        if (err) return callback (err, null)
        else return callback (null, pem)
    })
}

/*
@param spkac The spkac to be parsed.
@param callback The callback (err, result).

parse a spkac for it's challenge and publicKey
the resulting object is passed to the callback with the fields:
challenge, publicKey, valid.
*/
function parseSpkac(spkac, callback) {
    if (!spkac) return callback (new Error('invalid spkac'), null)
    else if (certificate.verifySpkac(spkac) === false)
        return callback (new Error('invalid spkac'), null)

    var rval = {
        challenge: certificate.exportChallenge(spkac),
        publicKey: certificate.exportPublicKey(spkac),
        valid: true
    }

    return callback (null, rval)
}

//
function parseForgeCert(cert, callback) {
    /*
    verify expected format.
    var validCert = {
        subject: { O: 'WebID', CN: 'Nicola Greco (test) [on test_nicola.databox.me]' },
        issuer: { O: 'WebID', CN: 'Nicola Greco (test) [on test_nicola.databox.me]' },
        subjectaltname: 'URI:https://test_nicola.databox.me/profile/card#me',
        modulus: 'C62AE4CE77A8D915527F79EE1B5365099A35A3BF8E4AA68ED7CBF4D6B966ACE0FCAD79DE66A0EA89FF5EF8DAB2619F51E2F28227C9AA594BA3A4176723BA00813D8F8C738359F6240DF8FADD1A7AE56F2B24E7329A189E1065E3E7C2CEC96CC57CD9D3BF782DC15C11FBEFD24E536C46E8E1285BEC27CB3CC6C295595F18BC564A6ACA45ABCB8AD0C6617F42F5151DDB1A42513BE7AA9E2593DFDBB03938C15136C202C61E59DFE7C563F56301B5B29F91C03A9C92458BA26918E22CB137B998FF76EC85E97D16424078A949F491E348D9E33A43C9D5D938C6E12B2F2015FA2C1A950E28C6ECC6DD70CE228275DBB4C085BC4063DA24178F5B13601E3E6CE17F',
        exponent: '10001',
        valid_from: 'Jan  1 00:00:00 2000 GMT',
        valid_to: 'Dec 31 23:59:59 2049 GMT',
        fingerprint: '17:09:CB:F5:8D:D7:49:BB:36:45:B8:96:01:C9:0F:0D:E7:56:5B:C0',
        serialNumber: '2A'
    }
    */

    var subject = cert.subject
    var subjPubKeyInfo = subject.getField('subjectPublicKeyInfo')
    var issuer = cert.issuer
    var getExt = cert.getExtension

    var rCert = {
        subject: { O: subject.getField('O'), CN: subject.getField('CN').value },
        issuer: { O: issuer.getField('O'), CN: issuer.getField('CN').value },
        subjectaltname: getExt('subjectAltName').value,
        modulus: '',
        exponent: '',
        valid_from: '',
        valid_to: '',
        fingerprint: '',
        serialNumber: ''
    }
    rCert.subject = cert.issuer.getField({name: 'commonName'}).value
}
