const nock = require('nock')
const utils = require('./utils')

const Tozny = require('@toznysecure/sdk/node')
const IDTools = require('../index')

Tozny.extend(IDTools)

const realmName = utils.saltString('id-tools-')
const appName = utils.saltString('eg-')
const apiDomain = `${utils.saltString('https://')}.com`
const domain = `${utils.saltString('https://')}.com`
const realmPath = `/auth/realms/${realmName}`
const infoPath = `${realmPath}/.well-known/openid-configuration`
const jwksPath = `${realmPath}/protocol/openid-connect/certs`

const realmInfo = {
  issuer: `${domain}${realmPath}`,
  jwks_uri: `${domain}${jwksPath}`

}
let realm
let verifier

beforeAll(async () => {
  // info and jwks mocks
  nock(apiDomain).persist().get(infoPath).reply(200, realmInfo)
  nock(domain).persist().get(jwksPath).reply(200, utils.jwksMock)

  // Set up verifier
  realm = new Tozny.identity.Realm(
    realmName,
    appName,
    '',
    apiDomain
  )
  verifier = Tozny.idTools.verifier(realm)
})

afterAll(async () => {
  nock.restore()
})

describe('ID Tools', () => {
  it('will decode a token', async () => {
    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer
      }
    )

    const {claims, headers} = await verifier.decode(token)
    // Verify some of the basic token claims and headers that came back from decode
    expect(headers.kid).toBe(utils.jwkMock.kid)
    expect(claims.sub).toBe(values.sub)
    expect(claims.jti).toBe(values.jti)
    expect(claims.azp).toBe(appName)
    expect(claims.iss).toBe(realmInfo.issuer)
  })

  it('will verify a token', async () => {
    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer
      }
    )

    const {claims} = await verifier.verify(token)
    // Verify some of the basic token claims came back from verify
    expect(claims.sub).toBe(values.sub)
    expect(claims.jti).toBe(values.jti)
    expect(claims.azp).toBe(appName)
    expect(claims.iss).toBe(realmInfo.issuer)
  })

  it('will verify a token with all options present', async () => {
    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer,
        scope: 'openid email profile'
      }
    )

    const {claims} = await verifier.verify(token, {
      authorizedParty: appName, // the application this token is expected to be issued for
      subject: values.sub, // the user uuid this token is expected to be issued for
      nonce: values.nonce, // the nonce expected to have been used for this authentication flow
      type: values.typ, // the type of token expect to have been issued
      scope: 'openid email profile', // the scope of the token claims expected (space separated list)
      sessionState: values.session_state, // the session state id the token is expected to contain
      authenticationContext: values.acr, // the authentication context class the token is expected to have
      keyID: values.kid, // the key ID the token is expected to have been signed with
      tokenType: 'JWT', // the token is expected to be a JSON Web Token
    })

    // Verify the token ID matches expected
    expect(claims.jti).toBe(values.jti)
  })

  it('will verify a different algorithms', async () => {
    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock3,
      {
        azp: appName,
        iss: realmInfo.issuer
      }
    )

    const {claims} = await verifier.verify(token)
    // Verify the token ID matches expected
    expect(claims.jti).toBe(values.jti)
  })

  it('will reject a token with an unknown kid', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer,
        kid: utils.jwkMock2.kid // this ID is not in the JWKS return
      }
    )

    // The key id is not available in the jwks
    await expect(verifier.verify(token)).rejects.toThrow()
  })

  it('will reject a token with a invalid signature', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock2,
      {
        azp: appName,
        iss: realmInfo.issuer,
        kid: utils.jwkMock.kid, // we claim this was signed by the main mock key
      }
    )

    // This token is properly signed, but by a different key than is in the jwks
    await expect(verifier.verify(token)).rejects.toThrow()
  })

  it('will reject an expired token', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer,
        auth_time: utils.nowInSeconds(-900), // 15 minutes ago
        iat: utils.nowInSeconds(-900), // 15 minutes ago
        exp: utils.nowInSeconds(-300), // 5 minutes ago
      }
    )

    // This token will not validate because it is expired
    await expect(verifier.verify(token)).rejects.toThrow()
  })

  it('will should respect a tolerance window', async () => {
    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer,
        auth_time: utils.nowInSeconds(-300), // 5 minutes minutes ago
        iat: utils.nowInSeconds(-300), // 5 minutes ago
        exp: utils.nowInSeconds(-5) // 5 seconds expired
      }
    )

    // 5 second expired token is within the 10 second tolerance
    const {claims} = await verifier.verify(token, {
      clockTolerance: 10 // 10 second tolerance
    })
    // Verify the token ID
    expect(claims.jti).toBe(values.jti)
  })

  it('should reject on an incorrect issuer', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: 'http://rando.example.com',
      }
    )

    // This will fail because the token issuer does not match TozID
    // This validation is performed automatically
    await expect(verifier.verify(token)).rejects.toThrow()
  })

  it('will verify the authorized party', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: 'differentapp', // this will not match our app
        iss: realmInfo.issuer
      }
    )

    // This will fail because the authorized party does not match
    await expect(verifier.verify(token, {
      authorizedParty: appName,
    })).rejects.toThrow()
  })

  it('will fail to verify an invalid subject', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer
      }
    )

    // This will fail because the authorized party does not match
    await expect(verifier.verify(token, {
      subject: '00000000-0000-0000-0000-000000000000',
    })).rejects.toThrow()
  })

  it('will fail to verify a invalid nonce', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer
      }
    )

    // This will fail because the nonce does not match
    await expect(verifier.verify(token, {
      nonce: '00000000-0000-0000-0000-000000000000',
    })).rejects.toThrow()
  })

  it('will fail to verify a invalid type', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer
      }
    )

    // This will fail because the nonce does not match
    await expect(verifier.verify(token, {
      type: 'actionToken',
    })).rejects.toThrow()
  })

  it('will fail to validate if an expected scope is missing', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer
      }
    )

    // This will fail because the email and profile scopes are missing
    await expect(verifier.verify(token, {
      scope: 'openid email profile',
    })).rejects.toThrow()
  })

  it('will validate if the token contains extra scopes', async () => {
    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer,
        scope: 'openid email profile'
      }
    )

    // This will succeed because only the openid scope is required
    const {claims} = await verifier.verify(token, {
      scope: 'openid'
    })
    // Verify the token ID
    expect(claims.jti).toBe(values.jti)
  })

  it('will fail to verify an invalid session state', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer,
      }
    )

    // This will fail because the session state is not the expected value
    await expect(verifier.verify(token, {
      sessionState: '00000000-0000-0000-0000-000000000000',
    })).rejects.toThrow()
  })

  it('will fail to verify an invalid authentication context', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer,
      }
    )

    // This will fail because the authentication context is not the expected value
    await expect(verifier.verify(token, {
      authenticationContext: '2',
    })).rejects.toThrow()
  })

  it('will fail to verify an invalid key ID', async () => {
    const {token} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: appName,
        iss: realmInfo.issuer,
      }
    )

    // This will fail because the key ID used to sign the token is not the expected value
    await expect(verifier.verify(token, {
      keyID: '00000000-0000-0000-0000-000000000000',
    })).rejects.toThrow()
  })

  it('will cache jwks responses', async () => {
    // Set up a new set of endpoints for a single test
    const singleRealm = utils.saltString('id-tools-')
    const singleApp = utils.saltString('eg-')
    const singleApiDomain = `${utils.saltString('https://')}.com`
    const singleDomain = `${utils.saltString('https://')}.com`
    const singleRealmPath = `/auth/realms/${singleRealm}`
    const singleInfoPath = `${singleRealmPath}/.well-known/openid-configuration`
    const singleJwksPath = `${singleRealmPath}/protocol/openid-connect/certs`
    const singleRealmInfo = {
      issuer: `${singleDomain}${singleRealmPath}`,
      jwks_uri: `${singleDomain}${singleJwksPath}`
    }

    // Set up mocks with expectations
    const infoApi = nock(singleApiDomain).get(singleInfoPath).times(1).reply(200, singleRealmInfo)
    const jwksApi = nock(singleDomain).get(singleJwksPath).times(1).reply(200, utils.jwksMock)

    // Set up verifier
    const singleTestRealm = new Tozny.identity.Realm(
      singleRealm,
      singleApp,
      '',
      singleApiDomain
    )
    const singleTestVerifier = Tozny.idTools.verifier(singleTestRealm, {logInfo: true})

    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: singleApp,
        iss: singleRealmInfo.issuer
      }
    )

    // Validate a token twice, this should work since the returns are caches in memory
    await singleTestVerifier.verify(token, { logInfo: true })
    const {claims} = await singleTestVerifier.verify(token, { logInfo: true })
    // Verify the token ID
    expect(claims.jti).toBe(values.jti)
    // Verify the nock mocks are done
    expect(infoApi.isDone()).toBe(true)
    expect(jwksApi.isDone()).toBe(true)
  })

  it('will have different caches in different instances', async () => {
    // Set up a new set of endpoints for a single test
    const singleRealm = utils.saltString('id-tools-')
    const singleApp = utils.saltString('eg-')
    const singleApiDomain = `${utils.saltString('https://')}.com`
    const singleDomain = `${utils.saltString('https://')}.com`
    const singleRealmPath = `/auth/realms/${singleRealm}`
    const singleInfoPath = `${singleRealmPath}/.well-known/openid-configuration`
    const singleJwksPath = `${singleRealmPath}/protocol/openid-connect/certs`
    const singleRealmInfo = {
      issuer: `${singleDomain}${singleRealmPath}`,
      jwks_uri: `${singleDomain}${singleJwksPath}`
    }

    // Set up mocks with expectations
    // accept calls twice to serve realm info to both verifiers
    nock(singleApiDomain).get(singleInfoPath).times(2).reply(200, singleRealmInfo)
    // Once to verify the second call fails as the cache is different and will miss
    nock(singleDomain).get(singleJwksPath).times(1).reply(200, utils.jwksMock)

    // Set up verifier
    const singleTestRealm = new Tozny.identity.Realm(
      singleRealm,
      singleApp,
      '',
      singleApiDomain
    )
    const singleTestVerifier = Tozny.idTools.verifier(singleTestRealm)
    const secondTestVerifier = Tozny.idTools.verifier(singleTestRealm) // allows uncached failure check

    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: singleApp,
        iss: singleRealmInfo.issuer
      }
    )

    // Validate a token twice, this should work since the returns are caches in memory
    const {claims} = await singleTestVerifier.verify(token)
    // Verify the token ID
    expect(claims.jti).toBe(values.jti)

    // A call with the second verifier should fail since the mock is only set up to respond once
    await expect(secondTestVerifier.verify(token)).rejects.toThrow()
  })

  it('will expire cache items that hit their expiration date', async () => {
    // Set up a new set of endpoints for a single test
    const singleRealm = utils.saltString('id-tools-')
    const singleApp = utils.saltString('eg-')
    const singleApiDomain = `${utils.saltString('https://')}.com`
    const singleDomain = `${utils.saltString('https://')}.com`
    const singleRealmPath = `/auth/realms/${singleRealm}`
    const singleInfoPath = `${singleRealmPath}/.well-known/openid-configuration`
    const singleJwksPath = `${singleRealmPath}/protocol/openid-connect/certs`
    const singleRealmInfo = {
      issuer: `${singleDomain}${singleRealmPath}`,
      jwks_uri: `${singleDomain}${singleJwksPath}`
    }

    // Set up mocks with expectations
    const infoApi = nock(singleApiDomain).get(singleInfoPath).times(1).reply(200, singleRealmInfo)
    const jwksApi = nock(singleDomain).get(singleJwksPath).times(2).reply(200, utils.jwksMock)

    // Set up verifier
    const singleTestRealm = new Tozny.identity.Realm(
      singleRealm,
      singleApp,
      '',
      singleApiDomain
    )
    const singleTestVerifier = Tozny.idTools.verifier(singleTestRealm)
    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: singleApp,
        iss: singleRealmInfo.issuer
      }
    )

    // Validate a token twice, this should work since the returns are caches in memory
    const {claims} = await singleTestVerifier.verify(token)
    // Verify the token ID
    expect(claims.jti).toBe(values.jti)
    // Verify the nock mock for info is done, but the jwks is not
    expect(infoApi.isDone()).toBe(true)
    expect(jwksApi.isDone()).toBe(false)

    // For expire the cache
    const newExpires = new Date(Date.now() - 1000) // one second ago
    for (let kid in singleTestVerifier.jwksCache._items) {
      // manually set expires to one second ago
      singleTestVerifier.jwksCache._items[kid].expires = newExpires
    }

    // A call with the second verifier should fail since the mock is only set up to respond once
    await singleTestVerifier.verify(token)
    // A second call should have been made, so the jwksApi is now done
    expect(jwksApi.isDone()).toBe(true)
  })

  it('will refresh the cache items when an unknown kid is seen', async () => {
    // Set up a new set of endpoints for a single test
    const singleRealm = utils.saltString('id-tools-')
    const singleApp = utils.saltString('eg-')
    const singleApiDomain = `${utils.saltString('https://')}.com`
    const singleDomain = `${utils.saltString('https://')}.com`
    const singleRealmPath = `/auth/realms/${singleRealm}`
    const singleInfoPath = `${singleRealmPath}/.well-known/openid-configuration`
    const singleJwksPath = `${singleRealmPath}/protocol/openid-connect/certs`
    const singleRealmInfo = {
      issuer: `${singleDomain}${singleRealmPath}`,
      jwks_uri: `${singleDomain}${singleJwksPath}`
    }

    // Set up mocks with expectations
    const infoApi = nock(singleApiDomain).get(singleInfoPath).times(1).reply(200, singleRealmInfo)
    const jwksApi = nock(singleDomain).get(singleJwksPath).times(2).reply(200, utils.jwksMock)

    // Set up verifier
    const singleTestRealm = new Tozny.identity.Realm(
      singleRealm,
      singleApp,
      '',
      singleApiDomain
    )
    const singleTestVerifier = Tozny.idTools.verifier(singleTestRealm)
    const {token, values} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: singleApp,
        iss: singleRealmInfo.issuer
      }
    )

    // Validate a token twice, this should work since the returns are caches in memory
    const {claims} = await singleTestVerifier.verify(token)
    // Verify the token ID
    expect(claims.jti).toBe(values.jti)
    // Verify the nock mock for info is done, but the jwks is not
    expect(infoApi.isDone()).toBe(true)
    expect(jwksApi.isDone()).toBe(false)

    // Save out the original expiration date
    const originalExpr = singleTestVerifier.jwksCache._items[utils.jwkMock.kid].expires
    // A call with the second verifier should fail since the mock is only set up to respond once
    const {token: token2} = await utils.makeTestJWT(
      utils.jwkMock,
      {
        azp: singleApp,
        iss: singleRealmInfo.issuer,
        kid: utils.saltString('')
      }
    )
    // This will fail because this is an unknown Key ID, but it should call the jwks endpoint to refresh
    await expect(singleTestVerifier.verify(token2)).rejects.toThrow()

    // A second call should have been made, so the jwksApi is now done
    expect(jwksApi.isDone()).toBe(true)
    // Validate the expiration date has changed for the primary key in the cache
    const newExpr = singleTestVerifier.jwksCache._items[utils.jwkMock.kid].expires
    expect(newExpr.getTime()).toBeGreaterThan(originalExpr.getTime())
  })
})
