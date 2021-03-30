const TokenVerifier = require('./src/tokenVerifier')

class IDTools {
  constructor(tozny, options) {
    this.tozny = tozny
    this.options = options
  }

  verifier(realm, options) {
    return new TokenVerifier(realm, options)
  }
}

IDTools.extensionName = 'idTools'

module.exports = IDTools
