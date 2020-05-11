import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'
import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth0Authorizer.ts')
const cert = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIJLmbKKVTusP9UMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNV
BAMTF2xva2VzaGdvdW5kZXIuYXV0aDAuY29tMB4XDTIwMDUwOTE1MDM1MloXDTM0
MDExNjE1MDM1MlowIjEgMB4GA1UEAxMXbG9rZXNoZ291bmRlci5hdXRoMC5jb20w
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBItSD1nRUx8Nz4j9kQeNP
PhL4XOfQNmeDRwDcNvW0XKo+Y1ZcMZwN7JG4E8IfN6j/kqVCE6HQYM42J+wkaM60
hsr7qeydlv+PTkAadbZQksoDXYwZkEMz48H5n4WYd1kS5ppiYv1cnlYjB2eYq69a
E7LQ70KuxORnUoblxobk+N52N+NR8zjUnDwQ90CHCDr1VFck02QfS+ejO7zFZPDD
WJ0prV8zqdqdUNTBSlnpLrbaI2RmAURx4V8z/7s4Gds0IX6xgmDiWZyUoNMgfNL5
bFbU9JtUwjQfwu2dZFmwkDLmXhmyRXhGJoc8fVREBhbfZh9zHx8zSEmcsKjr/qhn
AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOX3mulWDhltDHP0
I8VrJvP01j31MA4GA1UdDwEB/wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAkoob
mq0H1dLyO0x8VjW5Y4AYnQfFqSG+pxvlvN+0w5rWI1KQGXYhqu/mIfPMB4R7BULC
VO7mJ8oThidFYi1BwXq7OfYlyYtA7UwhIDKWvEI9uxdwFp+YE2wdlnwb4onYtHfl
mzjL7aH2of5RdzXVVikBQ5SxWoR5sv24lwW9Dt70EIdv2Tf2qV4IpCOhq3OeYgOL
vmLwNF/jcWccIJwtgW5U08SM1BylaO5FXYFqb+6kZHGF+diprZHJ1oiy9LRCxg7M
1rtNMjfRMgyn5tB2voj4JWQlV2IdTzXqBW5WVTWdT9YcHoaqLEpoWB/KE92ojSsm
Jor17wcXkcm/MlTjwA==
-----END CERTIFICATE-----`

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized: ', jwtToken)

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
    logger.error('User not authorized: ', { error: e.message })

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

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)

  return verify(token, cert, {algorithms: ['RS256']}) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}