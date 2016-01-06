exports.verify = verify
exports.verifyKey = verifyKey
exports.generate = generate

var $rdf = require('rdflib')
var get = require('../lib/get')
var parse = require('../lib/parse')
var forge = require('node-forge')
var crypto = require('crypto')
crypto.DEFAULT_ENCODING = 'buffer';
var certificate = new crypto.Certificate()
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

@author Cory Sabol
@email cssabol@uncg.edu
@param options The options object { spakc: clientkey, agent: uri }
@param callback The callback to be executed expects args: Error err, Cert certfificate
@return callback
The callback arg cert should be an object reprsentation of the certificate with
the psk12 format of the certificate.
*/
function generate(options, callback) {
    if (!options.agent) return callback(new Error('No agent uri found'), null)
    else if (!options.spkac) return callback(new Error('No public key found'), null)


    /* Usage example
    webid('tls').generate({
        spkac: req.body['spkac'],
        agent: agent
    }, callback)
    */

    // Generate a new keypair
    var keys = pki.rsa.generateKeyPair(2048)
	var cert = pki.createCertificate()
    var spkac = parseSpkac(options.spkac)
    cert.serialNumber = '01'
    // Convert the publicKey to a forge public key
    cert.publicKey = pki.publicKeyFromPem(spkac.publicKey)
    // Validity
	cert.validity.notBefore = new Date()
	cert.validity.notAfter = new Date()
	cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

    var attrs = [{
        name: 'commonName',
        value: options.commonName || options.agent
    }, {
        name: 'countryName',
        value: options.countryName || '.'
    }, {
        name: 'localityName',
        value: options.localityName || '.'
    }, {
        name: 'organizationName',
        value: options.organizationName || '.'
    }]

    cert.setSubject(attrs)
    cert.setIssuer(attrs)
    // Set the cert extensions
    cert.setExtensions([{
        name: 'subjectAltName',
        altNames: [{
            type: 6, // URI
            value: 'URI: ' + options.agent
        }]
    }])

    cert.sign(keys.privateKey)

    var rval = {
        modulus: cert.publicKey.n,
        exponent: cert.publicKey.e,
        // This needs to be some useful serialization other than a forge cert
        certificate: cert,
        ldCert: parseForgeCert(cert)
    }
}

/*
@param spkac The spkac to be parsed.
parse a spkac for it's challenge and publicKey
*/
function parseSpkac(spkac) {
    if (!spkac) throw new Error('no spkac specified')
    else if (certificate.verifySpkac(spkac) === false)
        throw new Error('invalid spkac')

    var rval = {
        // Note that these methods expect a <buffer>
        challenge: certificate.exportChallenge(spkac).toString(),
        publicKey: certificate.exportPublicKey(spkac).toString()
    }

    return rval
}

function parseForgeCert(cert) {
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
    var issuer = cert.issuer
    var altName = cert.getExtension('subjectAltName').altNames[0].value

    var rval = {
        subject: { O: subject.getField('O'), CN: subject.getField('CN').value },
        issuer: { O: issuer.getField('O'), CN: issuer.getField('CN').value },
        subjectaltname: altName,
        modulus: cert.publicKey.n.toString(),
        exponent: cert.publicKey.e.toString(),
        valid_from: cert.validity.notBefore.toString(),
        valid_to: cert.validity.notAfter.toString(),
        // This breaks at the native level saying that the URI is malformed
        // Need to look into this further
        // fingerprint: pki.getPublicKeyFingerprint(cert.publicKey).toString(),
        fingetprint: '',
        serialNumber: cert.serialNumber
    }

    return rval
}
