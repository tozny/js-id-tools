const { SignJWT } = require('jose/jwt/sign')
const { parseJwk } = require('jose/jwk/parse')
const { v4: uuidv4 } = require('uuid');


const jwkMock = {
  p:
    '5pHEsktNBgBiw2BY933FrubA6SMYP06SqOLJVhQdCtoMj_OOPkKhysVqtmIQLe6g30R6NICNL-eYQL9h8YnkvJdkwaDGLyYE-EygMw8W-REyFuTOw-Z7TH4cWZmbO9tefRLymD4pFNd-zDmP2LQI36JwDfwH5OWUKT1GFVRFc7c',
  kty: 'RSA',
  q:
    'tr4YhHoRFBBP7DQ2QCHY5TrNPWrsdFFOryttrSduKAxNBDUp8qAV0BH7MNga84PfqnWXYum_1pho8NKd2kd9uBEwpHwEyXGfsZU3J7NaJWfhMwPy2nvwqzlQ84-V3ALT3dNY3mJDHZ7SX3qjpUszf1RpjeXSwvVt2_8GkrMgtRU',
  d:
    'iH_RmqyZFd8zLELAsULJaC78AH9vbA7kyABg66NDRz3mqcf_zgS1WBg-5r8GyRSMSMDqu05zZj_XVWOAir0qwRTVGsNYUdJs4hWu_nbcdFbTQBkZ-XRpsT8KxrnXwo2_e1fpaFTqAQv-tGeHIJnHAhBuQcGnhTcmuHXvSA_FvajlOGZdWNmlO8Hton4QkXCQ788NeHNIS3Ar7i0CgRevOrOqXXiUqxS-442g34oWnr82-Cylb3nRSRzip02zxWuvgH5JXv-l6WsPE0_YXyZdOP6iQ0cZZ_-hL8JADJAx7IniiMLsW0VUNecnWoUK54WZTIY0r8brJiMUFAurJgbxgQ',
  e: 'AQAB',
  use: 'sig',
  kid: '53xuFc3gxzp_m06Qb_IcVcvcbXcEaMZLqK4V7GqR4nE',
  qi:
    'JymmcpVggBVQJ3gPO5HAwtM-vW69yKWBWmfC9jZx2yQ0GJj9Xrr7UqZpP5joX336CeyU71kndaSg8saXI0J8CP4H61wrQ2crUWzqqTNtaB9nD6yr077Cp9UBWtz-Cby7cyokDOy3tgBtRziX_eAZXus3tuKfetCGQy9XXcpuUlo',
  dp:
    'uS9ouP7r3R8gM-XFbvoQdTqWxGlQh0A3YPfNV5qN_PJG1rN6kpz3z6Gh5Nx8PDgF82zPbi21uD0dtxs_sjzbf3FlFnNn2eSCZ1875-Z9wAvEnEinnQYYD8bWREywNnIpwPEf8ZEzc67lA2hUFWv8GIohz8mWGY0e48R37pehtJ8',
  alg: 'RS256',
  dq:
    'ERFWJuFjwPT5Ef2aZ4kBwf8o9iiLZx3E9JVgzABXyIPFmbQBc_jBsMpNJLW6Zq4VcM1E02czlK5tdrilJ6LvugZY_bPbmpjzKlneaeXVcJLwNJyUzRUwWD2lMuphO8hD038O2M5iqFySF3rT1_dbGvReW3NwqObVWOvLyF3UmzU',
  n:
    'pJbYG7lnoeni9vwRIDIDq0JC_j7GZzxxc0AshPSw2HD0qB-LvzYMpUEk_0_e4SfQz8GK3y-fLwpQIgnmcciixUrJb9_8e33FULkqhd426k_EbCATYTUk4MQ4ZZuczvdX1oLZMMAa7otqfIZsGvu9gymZvvafpWkIltsvZHOEeM2NyzVptgbmi0Sg1JiARNC0Yx50D5EaG-Np1TWCNM8s9SJdAB0vK2i_zqPLjnkobAxvKMpdSz-wrZbXAa9wRPw265GaGTfQnlrZpzShcWxart0BuQWUDklYU3CKf7T3mSWKFnnVkpBxcPHTnYAo0saCxUKq1PJe0TPhxjVKcGLhAw',
}

const jwkMock2 = {
  p:
    'zHzHZvjubEyz-Nh26q7JDmLFBQMAW6gJ2NhRVTMT2cxjlxXmH6L33Sf3RhuODJ7VRtoiDqeYjKOWlBjJ4zMnfTlM_m_L1ktIYs8rbwj4uddPTGd2fF_NMFLknpBAKbc9va7kjL-cqvQZ53gorwNyv2_tVXx5iv38h5IxdPrl5JU',
  kty: 'RSA',
  q:
    'r3o2XzdbWbFk1SlqPnYMCU9anEveWfCRmacyw2VB_TcvXIUwhOGkqT85UjWGAEuPDsSQx4RLvOoAiX5HgV4zlOrUmpUcPZ8oUXm2h022CHDvdbZ4xvJvOF5j-f5BigW-9NKdGoh8VKvNTHBuHi_rERPMwMMUpAtxu_7a0T_yycU',
  d:
    'JTkQlUi7m3bF4rTHl8nRPM-VHlivRjm01utBcVei4ulNqKnWsrHGjAyuKUT-iqhFHdNtyxQ1fu9CP9DJzoBh5GYVfRQgSVrJGJIGOs3dON8NFAHJ2oUudJaQMYRxzN_Y1eM40q2SLw8M6fvWmiKNfUb29XVfr6Tq0fsqBohmkliUDIA00M29egFEoxHUs9LiAziVBymP0XL_foZMbAC5VHWhtLDWuKmy1OY7Q9BRgWeqObFoJ93vi9AzPmMLfZArY5wKmrn_AhexdVmsGBcic-2a3znA-AWFDkVpoVhoJHfTTOziCsf0vK2N8crXzfCK674ihwVa1il5khzKjdtqwQ',
  e: 'AQAB',
  use: 'sig',
  kid: 'KHW302AHLI9HGws0NcZiHDVTFXFqZPSM9wZHEOeFOFk',
  qi:
    'mEpRZr86qV-RZM-lU2rEz6jt1-1qEht9EVto9Ns4QS-7VBA5FZYttZw1notHiGpo0zqGBmIWJlrUq8620t5ThDXkY0jy7nu5O27QpC5uJOkQNoPWJSyh34O6entRhX_cnvlsFTQ2ibnutsZ-HQGEMcaPXBwdLHEG3OHaK7lhHQ0',
  dp:
    'wSeobxL6m6AEbC2Efn-leQpBEk_YebuLuaHziagauyN-ewt7eSzGNsf2oemLT06FJU0M2Izk4wvvQ2r64LrENVv352sQvxYThQot-88cqua_h-s_F5Kizl-uhjy57u2gy1i1mGGyiiTThzqQK2j1bfE63QIcCPeLH0AvqVEJ8NU',
  alg: 'RS256',
  dq:
    'PUZ62BL3hkGIyVq16-vC1jlslal0komL_lDBTDP-sBJmKnOj9rLokeUu-gMQsOexo-GGAPW0kNpRp7F9_LHNZ1H9PaGWA_qg1Jqg32yGhToSlFNMp4QezFtBpBlh_3V0Mf-dtpc0e0im3utfuJDZD9SPKjy053fLlm8vL-SZvlU',
  n:
    'jCrrNMvTHDfMIKKKr_GKioO0qHocV-q-_ofNHWAkolWOtXIxfWOC_4SXptl1fhIANRQ7_elMH18KDCpE1DLXS9cx4anxBLF9E_3dPU9A_xAISDw3uSVgOX-wGbie4SKA7_9GZaWUg5PqexkhzS6I2ju5G4pmzaT03RR5szHK2gscIpfjRNwiewxewF8RkxZAj0V3S2_JWc-ILCuW87nh6o2SB4Dz2jm67Ie8LbYMWkIlCl1usiE73qn9CE3YmnhxzpLkQO3ejUg3vfSihZB-yEaB0fw1wYiPWGrHX2h7ntyvwGftLNOfYGSQcxpie1RLqim7800FBSPj1Sg7UzvjqQ',
}

const jwkMock3 = {
  kty: 'EC',
  d: 'zecAOzcGXjjzXNkjHDOQ_zIjkZV8x_VR3Zyf1KNFRanDwyenFqAbcEEiubCDjYg9',
  use: 'sig',
  crv: 'P-384',
  kid: 'CObaEoaZR-S4879j-ucoEHJYwZyjLL5yTq12wd4Rekw',
  x: 'rhYweRjd2NQAbQY--lFKuh3ArwdUBWXfMH20NO-0UbGAlXg7-BTU791N5Km47cMx',
  y: '9DgPBtEb5_jWflbhC4yP4bYnGwmHq48W1yPoIJzGxDxTAQKPnKSGyXLmVyVycopt',
  alg: 'ES384',
}

const jwksMock = {
  keys: [
    {
      kid: jwkMock.kid,
      kty: jwkMock.kty,
      e: jwkMock.e,
      use: jwkMock.use,
      alg: jwkMock.alg,
      n: jwkMock.n,
    },
    {
      kty: jwkMock3.kty,
      use: jwkMock3.use,
      crv: jwkMock3.crv,
      kid: jwkMock3.kid,
      x: jwkMock3.x,
      y: jwkMock3.y,
      alg: jwkMock3.alg,
    },
  ],
}

function nowInSeconds(shift) {
  let seconds = Math.floor(Date.now() / 1000)
  if (shift) {
    seconds += shift
  }
  return seconds
}

function saltString(str) {
  return str + uuidv4()
}

async function makeTestJWT(signingKey, options = {}) {
  const privateKey = await parseJwk(signingKey)
  const values = {
    jti: options.jti || uuidv4(),
    sub: options.sub || uuidv4(),
    nonce: options.nonce || uuidv4(),
    sessionState: options.sessionState || uuidv4(),
    typ: options.typ || 'Bearer',
    acr: options.acr || '1',
    auth_time: options.auth_time || nowInSeconds(),
    session_state: options.sessionState || uuidv4(),
    scope: options.scope || 'openid',
    iat: options.iat || nowInSeconds(),
    exp: options.exp || nowInSeconds(300), // default 5 minutes from now
    alg: options.alg || signingKey.alg,
    kid: options.kid || signingKey.kid,
  }
  const claims = {
    typ: values.typ,
    acr: values.acr,
    auth_time: values.auth_time,
    nonce: values.nonce,
    session_state: values.session_state,
    scope: values.scope,
  }

  if (options.azp) {
    values.azp = options.azp
    claims.azp = options.azp
  }

  let token = new SignJWT(claims)
    .setProtectedHeader({alg: values.alg, kid: values.kid, typ: 'JWT'})
    .setSubject(values.sub)
    .setJti(values.jti)
    .setIssuedAt(values.iat)
    .setExpirationTime(values.exp)

  if (options.iss) {
    values.iss = options.iss
    token = token.setIssuer(options.iss)
  }

  token = await token.sign(privateKey)

  return {values, token}
}

module.exports = {
  jwkMock,
  jwkMock2,
  jwkMock3,
  jwksMock,
  nowInSeconds,
  makeTestJWT,
  saltString,
}
