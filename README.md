[![Build Status](https://travis-ci.org/tozny/js-id-tools.svg?branch=trunk)](https://travis-ci.org/tozny/js-id-tools)
# TozID Tools

A TozID extension that provides tools for relying parties.

## Quick Start

Install the TozID tools extension

```sh
npm install --save @toznysecure/id-tools
```

Add the extension to to the Tozny SDK

```js
import Tozny from '@toznysecure/sdk/node'
import IDTools from '@toznysecure/id-tools'

Tozny.extend(IDTools)

// Tozny.idTools is now available
```

## Available Tools

### Token validation

OIDC token validation can be difficult, but Tozny Identity tools simplifies the process. By providing a TozID Realm, you can begin validating tokens quickly and easily.

```js
const token = '...' // OIDC Token, 3 base64url encoded string separated by periods
const realm = new Tozny.identity.Realm(
  'realmName',
  'appName',
  'brokerURL',
  'apiURL',
)

const verifier = Tozny.idTools.verifier(realm)

async function validateToken(token) {
  // The issuer and JWKS to validate the token are loaded and cached for you.
  const validated = verifier.verify(token);

  // This is the full set of token claims as a Javascript object
  return validated.claims
}

validateToken(token).then(claims => {
  // Example: see if the token contains the client role for manage-account
  const canManageAccount = claims.resource_access.account.includes('manage-account')

})
```

When created, the verifier reaches out to TozID to fetch the public realm OIDC information, which includes the correct issuer and jwks URL. This data is cached in memory for the life of the verifier. Signatures are validated against keys at the JWKS url. As long as the token is signed by one of the available keys, has not expired, and has the correct issuer claim, it is considered valid. Additional options can be passed to the verify method and supported claims validation will be enforced.

 **Options:**

 - `clockTolerance` Controls how much clock drift is allowed when comparing issue and expiration dates. Default: 0
 - `maxTokenAge` Validates the 'iat' (issued at) claim is not older than the specified unix timestamp in seconds, accounting for clock tolerance
 - `tokenType` Validates the token header 'typ' matches the passed value
 - `keyID` Validates the token was signed by the key whose ID matches the passed value
 - `type` Validates the 'typ' claim matches the passed value
 - `subject` Validates the 'sub' claim matches the passed value
 - `audience` Validates the 'aud' claim contains the passed value
 - `authorizedParty` Validates the 'azp' (authorized party) claim matches the passed value
 - `nonce` Validates the 'nonce' claim matches the passed value
 - `scope` Validates the token scope claim contains all of the passed string of space separated scope names. Extra scopes in the token are ignored.
 - `authenticationContext` Validates the 'acr' claim matches the passed value
 - `sessionState` Validates the 'session_state' claim matchers the passed value

_Note: By default, TozID tokens do not contain 'aud' or 'nbf' claims, but they can get mapped into tokens for apps requiring it. For most tokens, validate the 'authorizedParty' matches your application as a baseline before trusting the token sent by a user._

```js
const {claims, headers} = await verifier.verify(token, {
  clockTolerance: 5, // 5 seconds of clock drift allowed
  maxTokenAge: 300, // 5 minutes in seconds, the issued at date must be within 5 minutes before now
  tokenType: 'JWT', // the token is expected to be a JSON Web Token
  keyID: '00000000-0000-0000-0000-000000000000', // the key ID the token is expected to have been signed with
  type: 'Bearer', // the type of token expect to have been issued
  subject: '00000000-0000-0000-0000-000000000000', // the user uuid this token is expected to be issued for
  audience: 'myApp', // the expected 'aud' claim, but is not mapped by default in TozID tokens
  authorizedParty: 'myApp', // the application this token is expected to be issued for
  nonce: '00000000-0000-0000-0000-000000000000', // the nonce expected to have been used for this authentication flow
  scope: 'openid email profile', // the scope of the token claims expected (space separated list)
  authenticationContext: '1', // the authentication context class the token is expected to have
  sessionState: '00000000-0000-0000-0000-000000000000', // the session state id the token is expected to contain
})
```

#### Token Decoding

In addition to the validate method, if you wish to decode a JWT without validating the signature or any claims, you can use the `decode` method

```js
const {claims, headers} = await verifier.decode(token)
```
## Terms of Service

Your use of the Tozny JavaScript SDK must abide by our [Terms of Service](https://tozny.com/tozny-terms-of-service/), as detailed in the linked document.
