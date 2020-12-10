
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
require('source-map-support').install();

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJBXDzujl1wL1OMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi1xdmN3aGd2ZC51cy5hdXRoMC5jb20wHhcNMjAxMjEwMTQyMzA4WhcN
MzQwODE5MTQyMzA4WjAkMSIwIAYDVQQDExlkZXYtcXZjd2hndmQudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNpMNJSRAgqjAdsf
HZDskaPgjZy3opgA3CS+xU5mHcbP6WBMwb+Jzk048W8VT8lhgbkDUHO3v+EV+UrO
2BpVpmvCwerLN/oKCNAlUfUwQR4S9ms4NTfehDmcuHanlWj1AfQ+FNPNLKCqmI0a
3s7SZ3HNBdVmBLzhYyv+0Kk6Uj/ZC3ZnTy+2d8yPForAMkxyPSI41+S+A9YNjnFV
I6rryLF20XPIklTNKrXGq89dXn8kCsS0QV2ipeo2ODHH91aZ/miw77tRrcGQDmOm
tm/5on01W1RGQhm9XaOiDUJsymjlrBXYy3cet38bhyVjYiqqgcVAScHMHHLBjzfj
95yXbwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQOsrFg2yyP
TaBD32V7P2bqldwOEjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AB94AuTVQnLrhT28Bd/IbrmBSFYeAPCGOUus9KeFBxBrTC6VROMDXOaAf++U4JMe
MAKcbnVDAjr4MnG2I55hN9HlpOaaH6jJtwvO98c6MonUpvpmldf31hm5Dol8dmS5
AtHkWuOOfDyuYPN2x2JDCWTUnSJ9Z1HCcpZ/cEerhuw5YeXppb5ijKIB3QdgvUYK
b3Vz2utlORhC63Az0QOmmq7qXWN62pJRRwjIT2eacEhG4VGsGgHcroRXLPaAqPq1
SBHgIPumxKYaihotJha5yHserhWjP5tSxLlPxNaACRuG7Znb+quMAM9M+4PPCWsv
6VeK5S1SXfB3nHSsESOW1eo=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
