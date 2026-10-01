import * as AWS from 'aws-sdk'
import { DocumentClient } from 'aws-sdk/clients/dynamodb'
import { TodoItem } from '../models/TodoItem'
import { TodoUpdate } from '../models/TodoUpdate'
import { TodoDelete } from '../models/TodoDelete'

export class TodoAccess {
  constructor(
    private readonly docClient: DocumentClient = createDynamoDBClient(),
    private readonly todosTable: string = process.env.TODOS_TABLE || ''
  ) {}

  async getAllTodos(userId: string): Promise<TodoItem[]> {
    const result = await this.docClient.query({
      TableName: this.todosTable,
      KeyConditionExpression: '#userId = :i',
      ExpressionAttributeNames: {
        '#userId': 'userId'
      },
      ExpressionAttributeValues: {
        ':i': userId
      },
    }).promise()
    return result.Items as TodoItem[]
  }

  async createTodoItem(todo: TodoItem): Promise<TodoItem> {
    await this.docClient.put({
      TableName: this.todosTable,
      Item: todo
    }).promise()
    return todo
  }

  async deleteTodoItem(todo: TodoDelete): Promise<TodoDelete> {
    await this.docClient.delete({
      TableName: this.todosTable,
      Key: todo
    }).promise()
    return todo
  }

  async updateTodoItem(todo: TodoUpdate): Promise<TodoUpdate> {
    await this.docClient.update({
      TableName: this.todosTable,
      Key: {
        userId: todo.userId,
        todoId: todo.todoId
      },
      UpdateExpression: 'set #nameId= :n, dueDate= :d, done= :dn',
      ExpressionAttributeNames: {
        '#nameId': 'name'
      },
      ExpressionAttributeValues: {
        ':n': todo.name,
        ':d': todo.dueDate,
        ':dn': todo.done
      }
    }).promise()
    return todo
  }
}

/** Create Dynamo Db */
function createDynamoDBClient(): DocumentClient {
  return new AWS.DynamoDB.DocumentClient()
}