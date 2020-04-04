import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda'
import 'source-map-support/register'
import * as AWS  from 'aws-sdk'
import * as uuid from 'uuid'

import * as middy from 'middy'
import { cors } from 'middy/middlewares'
import { getUserId } from '../../auth/utils'

const docClient = new AWS.DynamoDB.DocumentClient()
const groupsTable = process.env.GROUPS_TABLE

export const handler = middy(async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  console.log('Processing event: ', event)
  const itemId = uuid.v4()
  const authorization = event.headers.Authorization
  const split = authorization.split(' ')
  const jwtToken = split[1]
  
  const parsedBody = JSON.parse(event.body)
  const userId = getUserId(jwtToken)

  const newItem = {
    id: itemId,
    userId:userId,
    ...parsedBody
  }

  await docClient.put({
    TableName: groupsTable,
    Item: newItem
  }).promise()

  return {
    statusCode: 201,
    body: JSON.stringify({
      newItem
    })
  }
})

handler.use(
  cors({
    credentials: true
  })
)