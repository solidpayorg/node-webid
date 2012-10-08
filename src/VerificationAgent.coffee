request = require('request')
url = require('url')
rdf = require('../lib/node-rdflib.js')

# Based on :
# http://www.w3.org/2005/Incubator/webid/spec/drafts/ED-webid-20111212/
class WebID.VerificationAgent
  constructor: (certificate) ->
    @subjectAltName = certificate.subjectaltname
    @modulus = certificate.modulus
    @exponent = parseInt(certificate.exponent, 16).toString() # Convert to hex
    @uris = @subjectAltName.split(",")
    i = 0
    while i < @uris.length
      @uris[i] = @uris[i].split("URI:")[1]
      i++
      
  verify: (success, error, {waitFor}) ->
    @waitFor ?= 0 #wait for all requests
    @success = success
    @error = error
    if @uris.length is 0
      error 'certificateProvidedSAN'
    else
      uri = @uris.shift()
      @getWebID(uri)
        
  getWebID: (uri) ->
    parsedURI = url.parse(uri)
    
    options =
      url: parsedUrl
      method: 'GET'
      headers:
        Accept: 'application/rdf+xml,application/xhtml+xml,text/html'
    r = request options, (err, res, body) =>
      if err
        error 'profileGet'
      else
        @verifyWebID body
        
  verifyWebID: (webID) ->
    