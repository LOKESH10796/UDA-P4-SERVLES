# ?? Serverless TODO App

![Serverless](https://img.shields.io/badge/Serverless-Framework-red?style=for-the-badge&logo=serverless)
![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-orange?style=for-the-badge&logo=amazonaws)
![React](https://img.shields.io/badge/React-16.x-blue?style=for-the-badge&logo=react)
![Node.js](https://img.shields.io/badge/Node.js-14.x-green?style=for-the-badge&logo=node.js)

A fully serverless, highly scalable TODO application built using the Serverless Framework and AWS (Lambda, API Gateway, DynamoDB, S3).

## ?? Features

* **Serverless Backend:** REST API built with Node.js and AWS Lambda.
* **NoSQL Database:** Data persisted in AWS DynamoDB for fast reads and writes.
* **Authentication:** Integrated with Auth0 for secure user authentication (JWT).
* **Storage:** Image attachments stored securely in AWS S3.
* **Modern Frontend:** React client with a clean UI to manage TODOs.
* **CI/CD:** Automated deployment via GitHub Actions.

## ??? Architecture

The backend consists of several microservices deployed as AWS Lambda functions:
- \Auth\: Custom authorizer to validate JWT tokens.
- \GetTodos\: Fetch all TODO items for a user.
- \CreateTodo\: Create a new TODO item.
- \UpdateTodo\: Update an existing TODO.
- \DeleteTodo\: Remove a TODO.
- \GenerateUploadUrl\: Generate a presigned S3 URL for secure image uploads.

## ?? Setup & Deployment

1. **Install Serverless Framework:** \
pm install -g serverless\
2. **Deploy Backend:**
   \\\ash
   cd backend
   npm install
   sls deploy -v
   \\\
3. **Run Frontend locally:**
   \\\ash
   cd client
   npm install
   npm start
   \\\

## ?? License

This project is licensed under the MIT License.
