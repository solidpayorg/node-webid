request = require('request')
url = require('url')
rdfstore = require('rdfstore')

# Based on :
# http://www.w3.org/2005/Incubator/webid/spec/drafts/ED-webid-20111212/
class WebID.VerificationAgent
  constructor: (certificate) ->
    @uris = []
    @subjectAltName = certificate.subjectaltname
    @modulus = certificate.modulus
    @exponent = parseInt(certificate.exponent, 16).toString() # Convert to hex
    @subjectAltName.replace /URI:([^, ]+)/g, (match, uri) =>
      @uris.push uri
      
  verify: (success, error, {}) ->
    @waitFor ?= 0 #wait for all requests
    if @uris.length is 0
      error 'certificateProvidedSAN'
    else
      uri = @uris.shift()
      @getWebID uri, success, error
        
  getWebID: (uri, success, error) ->
    parsedURI = url.parse(uri)
    
    options =
      url: parsedURI
      method: 'GET'
      headers:
        Accept: 'text/turtle, application/ld+json'
    r = request options, (err, res, body) =>
      if err
        error 'profileGet'
      else
        @verifyWebID uri, body, res.headers['content-type'], success, error
        
  verifyWebID: (webID, profile, mimeType, successCB, errorCB) =>
    rdfstore.create (store) =>
      store.load mimeType, profile, (success, results) =>
        if success
          store.execute "PREFIX cert: <http://www.w3.org/ns/auth/cert#> SELECT ?webid ?m ?e WHERE { ?webid cert:key ?key . ?key cert:modulus ?m . ?key cert:exponent ?e . }", (success, results) =>
            if success
              i = 0
              while i < results.length
                modulus = null
                exponent = null
                if results[i].webid.value is webID
                  modulus = results[i].m.value
                  exponent = results[i].e.value
                  # Check if the modulus and exponent are equals
                  if modulus? and exponent? and (modulus.toLowerCase() is @modulus.toLowerCase()) and (exponent is @exponent)
                    # Every thing is OK, webid valid
                    successCB webID
                    return undefined
                i++
              errorCB "profileAllKeysWellFormed"
            else
              errorCB "profileAllKeysWellFormed"
        else
          # Can't load 
          errorCB "profileWellFormed" 