# Secure Employee Payment Portal

## Overview
A secure payment portal with role-based access control,
featuring customer and employee interfaces. Built with React.js,
Node.js, Express, and MongoDB, implementing advanced security measures
and following best practices.


## Features

### Security Features
- Argon2 password hashing
- Rate limiting for login attempts
- Session management with secure cookies
- HTTPS/SSL encryption
- XSS protection
- CORS security
- MongoDB sanitization
- Input validation
- Activity logging
- Error tracking

### User Management
- Role-based access control (Customer/Employee)
- Secure user registration
- Session handling
- Login attempt tracking
- Password strength validation

### Payment Processing
- Secure payment submission
- Payment tracking
- Transaction history
- Payment validation
- Status monitoring
- Employee payment overview

### Monitoring & Logging
- Activity logging
- Error tracking
- Login attempt monitoring
- Session tracking
- Health endpoints

## Technologies Used
- Frontend:
  - React.js
  - React Router
  - TailwindCSS
  - Session Storage
  
- Backend:
  - Node.js
  - Express.js
  - MongoDB Atlas
  - Argon2 (Password Hashing)
  
- Security:
  - HTTPS/SSL
  - Helmet
  - Express Rate Limit
  - XSS Clean
  - MongoDB Sanitize

## Prerequisites
- Node.js (v14 or higher)
- MongoDB Atlas account
- SSL certificates (for HTTPS)
- npm or yarn

## Installation

1. Clone the repository
```bash
git clone [repository-url]
```

2. Install server dependencies
```bash
cd server
npm install
```

3. Install client dependencies
```bash
cd client
npm install
```

4. Create .env file in server directory
```env
PORT=3001
MONGODB_URI=your_mongodb_connection_string
NODE_ENV=development
FRONTEND_URL=https://localhost:3000
```

5. Add SSL certificates in server directory
- key.pem
- cert.pem

## Running the Application

1. Start the server
```bash
cd server
node server.js
```

2. Start the client
```bash
cd client
npm start
```

## Database Schema

### Users Collection
```javascript
{
  username: String,
  accountNumber: String,
  password: String (hashed),
  role: String ('customer' or 'admin'),
  createdAt: Date,
  lastLogin: Date,
  status: String,
  failedLoginAttempts: Number
}
```

### Payments Collection
```javascript
{
  customerName: String,
  customerAccountNumber: String,
  amount: Number,
  recipientName: String,
  accountNumber: String,
  bankName: String,
  reference: String,
  paymentDate: Date,
  status: String,
  timestamp: Date,
  createdAt: Date
}
```

### Activity Logs Collection
```javascript
{
  type: String,
  details: Object,
  success: Boolean,
  timestamp: Date,
  environment: String
}
```

## API Endpoints

### Authentication
- `POST /api/login` - User authentication
- `POST /api/register-customer` - Customer registration
- `POST /api/logout` - User logout
- `GET /api/check-session` - Session validation

### Payments
- `POST /api/payments` - Create new payment
- `GET /api/payments` - Get all payments (Employee only)

### System
- `GET /api/health` - System health check

## Security Features
- Password hashing with Argon2
- Rate limiting for login attempts
- Session management
- HTTPS/SSL encryption
- XSS protection
- CORS configuration
- Input validation
- MongoDB sanitization

## Role-Based Access
### Customer Features
- Make payments
- View own payment history
- Manage account details

### Employee Features
- View all customer payments
- Monitor payment status
- Access transaction history

## Error Handling
- Comprehensive error logging
- Activity tracking
- Failed login attempt monitoring
- Detailed error messages (in development)
- Secure error responses

## Authors
~ Nathan Nayager: ST10039749
~ Bianca Marcell Munsami: ST10069986
~ Bai Hong He(Jackie):ST10030735
~ Cristina Rodrigues:ST10049126
~ Uzair:ST10045844

## Acknowledgments
- MongoDB Atlas for database hosting
- React and Node.js communities
- Security best practices references
