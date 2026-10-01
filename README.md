# ⚡ Serverless Cloud TODO Architecture

[![AWS Lambda](https://img.shields.io/badge/AWS_Lambda-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com/lambda/)
[![Amazon DynamoDB](https://img.shields.io/badge/Amazon_DynamoDB-4053D6?style=for-the-badge&logo=Amazon%20DynamoDB&logoColor=white)](https://aws.amazon.com/dynamodb/)
[![Serverless](https://img.shields.io/badge/Serverless-FD5750?style=for-the-badge&logo=serverless&logoColor=white)](https://www.serverless.com/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20.x-339933?style=for-the-badge&logo=node.js)](https://nodejs.org/)
[![Auth0](https://img.shields.io/badge/Auth0-EB5424?style=for-the-badge&logo=auth0&logoColor=white)](https://auth0.com/)

A modern, highly scalable Serverless application demonstrating enterprise-level AWS architecture. This project implements a fully distributed backend using the Serverless Framework to provision AWS API Gateway, Lambda functions, DynamoDB NoSQL tables, and secure S3 presigned URL uploads.

## 🏗️ Cloud Infrastructure Diagram

```mermaid
flowchart TD
    Client([📱 React SPA Client])
    Auth0{{🔐 Auth0 (JWT)}}
    
    subgraph AWS Cloud Serverless Architecture
        APIGW[[⚡ API Gateway]]
        
        subgraph Lambda Microservices
            Auth[Custom Authorizer]
            GetTodos[GET /todos]
            CreateTodo[POST /todos]
            UpdateTodo[PATCH /todos]
            DeleteTodo[DELETE /todos]
            UploadURL[POST /attachment]
        end
        
        DynamoDB[(🗄️ DynamoDB\nPay-per-request)]
        S3[(🪣 AWS S3\nImage Bucket)]
    end
    
    Client -- 1. Authenticates --> Auth0
    Client -- 2. API Requests (JWT) --> APIGW
    
    APIGW -- Validates Token --> Auth
    Auth -- Authorized --> APIGW
    
    APIGW --> GetTodos
    APIGW --> CreateTodo
    APIGW --> UpdateTodo
    APIGW --> DeleteTodo
    APIGW --> UploadURL
    
    GetTodos & CreateTodo & UpdateTodo & DeleteTodo -- Read/Write --> DynamoDB
    UploadURL -- Presigned URLs --> S3
    Client -- 3. Direct Uploads (Presigned URL) --> S3
```

## ✨ Enterprise Features
- **Serverless Compute**: Fully managed AWS Lambda functions running Node 20.x (`xray` distributed tracing enabled).
- **Custom Authorization**: AWS API Gateway Custom Authorizers seamlessly validating Auth0 JWT tokens in real-time.
- **Secure File Storage**: S3 buckets configured with Presigned URLs to allow the client to upload images securely without routing heavy binary payloads through API Gateway.
- **NoSQL Persistence**: High-throughput AWS DynamoDB configured with Composite Keys (Hash + Range) for fast, user-isolated data retrieval.
- **Infrastructure as Code (IaC)**: The entire AWS backend is codified in `serverless.yml` for declarative and reproducible infrastructure deployments.

## 🚀 Deployment Guide

### Backend Setup (AWS)
Requires an active AWS Account and configured AWS CLI (`~/.aws/credentials`).

```bash
# 1. Navigate to backend
cd backend

# 2. Install dependencies
npm install

# 3. Deploy the entire infrastructure to AWS
npx serverless deploy --verbose
```

### Frontend Setup (React)
```bash
# 1. Navigate to client
cd client

# 2. Install dependencies
npm install

# 3. Configure API Endpoint
# Update the API endpoint in src/config.ts to match your newly deployed API Gateway URL.

# 4. Run Development Server
npm start
```

## 👨‍💻 Cloud Architect
Engineered by **Lokesh Gounder**  
📧 [lokeshgounder@gmail.com](mailto:lokeshgounder@gmail.com)  
🔗 [GitHub Profile](https://github.com/LOKESH10796)
