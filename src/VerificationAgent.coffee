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
        #Acording to http://richard.cyganiak.de/blog/2008/03/what-is-your-rdf-browsers-accept-header/
        Accept: 'application/rdf+xml, application/xhtml+xml;q=0.3, text/xml;q=0.2,application/xml;q=0.2, text/html;q=0.3, text/plain;q=0.1, text/n3,text/rdf+n3;q=0.5, application/x-turtle;q=0.2, text/turtle;q=1'
    r = request options, (err, res, body) =>
      if err
        error 'profileGet'
      else
        #type is res.headers['content-type']
        @verifyWebID uri, body, success, error
        
  verifyWebID: (webID, profile, successCB, errorCB) =>
    rdfstore.create (store) =>
      store.load "text/turtle", profile, (success, results) =>
        if success
          store.execute "PREFIX cert: <http://www.w3.org/ns/auth/cert#> SELECT ?webid ?m ?e WHERE { ?webid cert:key ?key . ?key cert:modulus ?m . ?key cert:exponent ?e . }", (success, results) =>
            if success
              modulus = null
              exponent = null
              i = 0
              while i < results.length
                if results[i].webid #and results[i].webid.value is webidUri
                  modulus = results[i].m.value
                  exponent = results[i].e.value
                i++
              if modulus? and exponent?
                # Check if the modulus and exponent are equals
                if (modulus.toLowerCase() is @modulus.toLowerCase()) and (exponent is @exponent)
                  # Every thing is OK, webid valid
                  # Transform store to graph
                  store.node webID, (success, graph) ->
                    successCB graph
                else
                  # The certificate does not identity this FOAF file
                  errorCB "falseWebID"
              else
                errorCB "profileAllKeysWellFormed"
            else
              errorCB "profileAllKeysWellFormed"
        else
          # Can't load 
          errorCB "profileWellFormed" 