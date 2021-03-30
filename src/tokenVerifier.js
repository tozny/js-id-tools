const fetch = require('cross-fetch')
const MemoryCache = require('./memoryCache')
const { parseJwk } = require('jose/jwk/parse')
const { jwtVerify } = require('jose/jwt/verify')
const { JWTClaimValidationFailed, JWTInvalid } = require('jose/util/errors')

class TokenVerifier {
  /**
   * Create a token verifier to decode, validate, and verify TozID JWTs
   *
   * This allows straight forward validation of tokens issued by a TozID realm.
   * The `validate` method will check a tokens signature against keys from the
   * realms JWKS endpoint, and perform claim validation.
   *
   * Options allows behavioral control over the internal behavior of the
   * validator. Available options are:
   *
   * - `jwksTimeout` How long in seconds a key from the JWKS endpoint will get cached. Defualt: 86400 (1 day)
   * - `jwksCache` A more robust cache can be provided allowing more robust caching backend ors caches share across verifiers. Default: MemoryCache
   *
   * @param {object} realm The Tozny Identity realm object
   * @param {object} options A set of options for controlling verifier behavior
   */
  constructor(realm, options = {}) {
    this.jwksCache = options.jwtCache || new MemoryCache()
    this.jwksTimeout = options.jwksTimeout || 86400 // default one day
    this.crypto = realm.crypto
    this.oidcInfo = fetch(
      `${realm.apiUrl}/auth/realms/${realm.realmDomain}/.well-known/openid-configuration`
    ).then((info) => info.json())
  }

  /**
   * Verify a JWT signature and claims, keys coming from the JWKS and cache
   *
   * This will validate that signature on a JWT passed in was signed by a key
   * available at the TozID JWKS endpoint, and has not expired. It will also
   * automatically validate that the issuer in the token matches the TozID
   * issuer for the configured realm.
   *
   * In addition to the default behavior, options allow additional validation
   * control allowing easy validation of standard and TozID claims. If the option
   * is not passed or undefined, it will not get validated. Available
   * options are:
   *
   * - `clockTolerance` Controls how much clock drift is allowed when comparing issue and expiration dates. Default: 0
   * - `tokenType` Validates the token header 'typ' matches the passed value
   * - `keyID` Validates the token was signed by the key whose ID matches the passed value
   * - `type` Validates the 'typ' claim matches the passed value
   * - `subject` Validates the 'sub' claim matches the passed value
   * - `audience` Validates the 'aud' claim contains the passed value
   * - `maxTokenAge` Validates the 'iat' (issued at) claim is not older than the specified unix timestamp in seconds, accounting for clock tolerance
   * - `authorizedParty` Validates the 'azp' (authorized party) claim matches the passed value
   * - `nonce` Validates the 'nonce' claim matches the passed value
   * - `authenticationContext` Validates the 'acr' claim matches the passed value
   * - `sessionState` Validates the 'session_state' claim matchers the passed value
   * - `scope` Validates the token scope claim contains all of the passed string of space separated scope names. Extra scopes in the token are ignored.
   *
   * _Note: By default, TozID tokens do not contain 'aud' or 'nbf' claims, but they can
   * get mapped into tokens for apps requiring it. For most tokens, validate the
   * 'authorizedParty' matches your application as a baseline before trusting
   * the token sent by a user._
   *
   * @param {string} token copy
   * @param {object} options The verification options allowing choice of information to validate
   * @returns {object}
   */
  async verify(token, options = {}) {
    const info = await this.oidcInfo
    const verificationOptions = Object.assign({}, options, {
      issuer: info.issuer,
    })
    // Juggle the type option to the correct jose typ claim as needed
    if (options.tokenType) {
      verificationOptions.typ = options.tokenType
      delete verificationOptions.tokenType
    }
    // Primary signature verification and claims validation
    const { payload, protectedHeader } = await jwtVerify(
      token,
      async (header) => this.getKey(header.kid, !!options.forceRefreshJWKS),
      verificationOptions
    )
    // Additional validation
    if (options.authorizedParty && payload.azp !== options.authorizedParty) {
      throw new JWTClaimValidationFailed(
        "unexpected 'azp' claim value",
        'azp',
        'check_failed'
      )
    }
    if (options.nonce && payload.nonce !== options.nonce) {
      throw new JWTClaimValidationFailed(
        "unexpected 'nonce' claim value",
        'nonce',
        'check_failed'
      )
    }
    if (options.type && payload.typ !== options.type) {
      throw new JWTClaimValidationFailed(
        "unexpected 'typ' claim value",
        'typ',
        'check_failed'
      )
    }
    if (
      options.authenticationContext &&
      payload.acr !== options.authenticationContext
    ) {
      throw new JWTClaimValidationFailed(
        "unexpected 'acr' claim value",
        'acr',
        'check_failed'
      )
    }
    if (
      options.sessionState &&
      payload.session_state !== options.sessionState
    ) {
      throw new JWTClaimValidationFailed(
        "unexpected 'session_state' claim value",
        'session_state',
        'check_failed'
      )
    }
    if (options.scope) {
      const requiredScopes = options.scope.split(' ')
      const tokenScopes = payload.scope.split(' ')
      const missingScopes = []
      for (let scope of requiredScopes) {
        if (! tokenScopes.includes(scope)) {
          missingScopes.push(scope)
        }
      }
      if (missingScopes.length > 0) {
        throw new JWTClaimValidationFailed(
          `missing values (${missingScopes.join(', ')}) in the 'scope' claim`,
          'scope',
          'check_failed'
        )
      }
    }
    if (options.keyID && protectedHeader.kid !== options.keyID) {
      throw new JWTInvalid(
        `expected token to be signed with ${options.keyID} but it was signed with ${protectedHeader.kid}`
      )
    }
    // Everything validates
    return { claims: payload, headers: protectedHeader }
  }

  /**
   * Decode a JWT string without validation the signature or claims
   *
   * @param {string} token A valid, base64url JWT string to decode
   * @returns {object} The decoded header and claims from the token
   */
  decode(token) {
    if (typeof token !== 'string') {
      throw new JWTInvalid(
        'A JWT is a string of 3 period separated base64 values'
      )
    }
    const { 0: encodedHeader, 1: encodedClaims, length } = token.split('.')
    if (length !== 3) {
      throw new JWTInvalid(
        'A JWT is a string of 3 period separated base64 values'
      )
    }
    const headers = JSON.parse(this.crypto.platform.b64URLDecode(encodedHeader))
    const claims = JSON.parse(this.crypto.platform.b64URLDecode(encodedClaims))

    return { headers, claims }
  }

  /**
   * Find a key either from cache, or fetching from the configured JWKS endpoint
   *
   * If the key is found in the cache, it will return that without hitting the
   * JWKS endpoint, otherwise it will fetch the keys available at the JWKS
   * endpoint and add each to the cache referenced by key ID. If refresh is
   * sent as true, the cache JWKS endpoint will be queried even if the key
   * in question is already in the cache and has not expired.
   *
   * Cache expiration times are controlled by the jwksTimeout option.
   *
   * @param {string} keyID The Key ID to find in the cache or JWKS endpoint
   * @param {bool} refresh Whther to force a cache refresh, even on a hit
   * @returns {JWK} A JSON Web Key object for use in validating a token signature
   */
  async getKey(keyID, refresh = false) {
    const info = await this.oidcInfo
    let cached = this.jwksCache.get(keyID)
    if (!cached || refresh) {
      const response = await fetch(info.jwks_uri)
      if (!response.statusCode === 200) {
        const message = await response.text()
        throw new Error(
          `Unable to fetch JWKS (${response.statusCode}): ${message}`
        )
      }
      const set = await response.json()
      const expires = new Date(Date.now() + this.jwksTimeout * 1000)
      this.jwksCache.clear()
      for (let key of set.keys) {
        const parsed = await parseJwk(key)
        if (key.kid === keyID) {
          cached = parsed
        }
        this.jwksCache.set(key.kid, parsed, expires)
      }
    }
    if (!cached) {
      throw new Error(
        `Key ID "${keyID} not found at the JWKS URI ${this.jwksUri}"`
      )
    }
    return cached
  }
}

module.exports = TokenVerifier
