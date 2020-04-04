
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'
import { JwtToken } from '../../auth/JwtToken'
import { verify } from 'jsonwebtoken'

const certi = `-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIJfccqaEu1LM9HMA0GCSqGSIb3DQEBCwUAMB8xHTAbBgNV
BAMTFHByYXZpbi1kZXYuYXV0aDAuY29tMB4XDTIwMDQwMzE4MjMwMloXDTMzMTIx
MTE4MjMwMlowHzEdMBsGA1UEAxMUcHJhdmluLWRldi5hdXRoMC5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5uNVtFr2sQ8iz8wBruDw1tAgHUXPU
IpzpY6fyhKls+wvji9CIztj37SKlIU6tp8taGOxV3wSyGFHEviJlaVBni4HMLkFm
qmj4L4G0i+1iugTHtJ4AVQHWqnspxiSdtxDVO80YVGgHnYQedJOKOMqPIT65ZI4i
aWfEdrwwNueoFI9P3hvMgc4YTKwTCxDSPrngwIoX+ysH3R5FZRUoVyER7Sxllqg8
KisD4TMRBNZaUQ+RaG2wvb0A8dTI7tTYoKbXWx05CTxGviJaso5iC//4yqZbBAe7
4ZmFdgYstEzUMLdN+0WXizItgNmAu5R5PJmxa+Cj38Rp7cQtve4KhHZ3AgMBAAGj
QjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFFKKlZOzxJodCJc8xi3JJWSa
vDvVMA4GA1UdDwEB/wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAsdCxUtj4Deb8
4ub8bkUqJX9AhJQVt+3h6dSaeu/SwdoE9HVwTHE+CA6ie/CH+5e6oljuu5A0g6I4
oXBuT17WZDIYardYT3Sp1MoSGy1Ei6B9xBvjyotAMaGXV7rjIafBwCIdf/ALX7ph
IpAL0UhcfPdQCWD/KBSXJwVOXB/V4cYAbtTSqNd9zj8Nu5jzjCgmL5gjjT4DSBJn
pvnKNJpr0U3U+uFAYfKARNzO8Pw+qpRN+LCnBgEmO98tT+HV6LRq/RByZPZgEF9B
oNtsFQZCbnayKr+ow3RP/K4pB2qscfKHBP5STGUTU8RgmlRe7wZAy5aUNjMDdC8X
N6YCDGm+6A==
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const decodedToken = verifyToken(event.authorizationToken, certi)

    console.log('User was authorized', decodedToken)

    return {
      principalId: decodedToken.sub,
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
    console.log('User was not authorized', e.message)

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

function verifyToken(authHeader: string, cert: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(
    token,
    cert,
    { algorithms: ['RS256'] }) as JwtToken
}