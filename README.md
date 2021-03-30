# TozID Tools

A TozID extension that provides tools for relying parties.

## Quickstart

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

OIDC token validation can be difficult, but Tozny Identity tools simplifies the process.
