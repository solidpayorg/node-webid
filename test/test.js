var WebID = require('../index')
var assert = require('assert')

var validCert = {
  subject: { O: 'WebID', CN: 'Nicola Greco [on nicola.databox.me]' },
  issuer: { O: 'WebID', CN: 'Nicola Greco [on nicola.databox.me]' },
  subjectaltname: 'URI:https://nicola.databox.me/profile/card#me',
  modulus: 'BBAF9C691762D6C66B66912CBD7ADB1804BAC634834A6F829184C9DF2BB76A312B23267BC45807D0AFDF53B84D4AC78A77314295B71325EA488BEDEDDF44EA730C33E5E1D7C98807FCDAA8B6FE72AE994CACD477E40DD90AF67696B7EB8EF12D2519414B00B9C5C87FF85876E5C49E66A73C44AC1C1CB7A7152EBB65E7FAC84615F81FA3066D90983B468E2E5CC68B345460F51F02CA477A2987FDB83EC1DB067613B561F256341EB619FD914ED5FFCE7194D9A8D26B345A90BF9CC5D4AE8B4B793D32936EE91DEC3F12B28744D0DCFB7A7D77C7215DAB0778CF3D3FE4201DAACA93C9FAA6E7C7869DF0DE50CE48B04311F050EAA9749F5B1C8F040C4E7B1657',
  exponent: '10001',
  valid_from: 'Jan  1 00:00:00 2000 GMT',
  valid_to: 'Dec 31 23:59:59 2049 GMT',
  fingerprint: 'DE:31:97:12:BE:A9:4A:8D:6C:B0:87:5C:E3:3F:10:7C:CF:0B:BE:DB',
  serialNumber: '2A'
}

describe('WebID', function () {
  this.timeout(10000);

  describe('Verification Agent', function (err, result) {

    it('valid certificate should have a result', function (done) {
      var agent = new WebID.VerificationAgent(validCert)
      agent.verify(function (err, result) {
        console.log(err, result, typeof result)
        assert(!!result)
        assert(!err)

        var foaf = new WebID.Foaf(result);
        console.log(foaf.parse())

        done()
      })
    })


    it('should throw error certificate is missing or empty', function () {
      var cert = null
      assert.throws(function () {
        var agent = new WebID.VerificationAgent(cert)
      }, Error)

      var cert = {}
      assert.throws(function () {
        var agent = new WebID.VerificationAgent(cert)
      }, Error)
    })


  })
})
