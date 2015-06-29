var WebID = require('../index')
var assert = require('assert')

describe('WebID', function() {

  describe('Verification Agent', function(err, result) {
  
    it('should throw error certificate is missing', function() {
      var cert = null
      assert.throws(function() {
        var agent = new WebID.VerificationAgent(cert)
      }, Error)
    })

    it('should throw error certificate is empty', function() {
      var cert = {}
      assert.throws(function() {
        var agent = new WebID.VerificationAgent(cert)
      }, Error)
    })
  })
})