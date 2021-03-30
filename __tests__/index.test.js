const Tozny = require('@toznysecure/sdk/node')
const IDTools = require('../index')

Tozny.extend(IDTools)

describe('ID Tools', () => {
  it('can be installed', () => {
    expect(Tozny.idTools).toBeInstanceOf(IDTools)
  })
})
