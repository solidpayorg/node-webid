var WebID = require('../index')
var assert = require('assert')

describe('WebID', function() {

  describe('Verification Agent', function(err, result) {
  
    it('should throw error certificate is missing or empty', function() {
      var cert = null
      assert.throws(function() {
        var agent = new WebID.VerificationAgent(cert)
      }, Error)

      var cert = {}
      assert.throws(function() {
        var agent = new WebID.VerificationAgent(cert)
      }, Error)
    })
  })
})