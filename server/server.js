require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const argon2 = require('argon2');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const session = require('express-session');

const app = express();

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    referrerPolicy: { policy: 'same-origin' }
}));

app.use(session({
    secret: crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'none',
        maxAge: 30 * 60 * 1000
    }
}));

app.use(cors({
    origin: ['http://localhost:3000', 'https://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Accept', 'Authorization']
}));

app.use(express.json({ limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});

const registrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour window
    max: 3, // limit to 3 registrations per hour
    message: 'Too many registration attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later.'
});

app.use('/api/login', loginLimiter);
app.use('/api/register-customer', registrationLimiter);
app.use('/api/', apiLimiter);

const VALIDATION_PATTERNS = {
    username: /^[a-zA-Z0-9_]{4,20}$/,
    accountNumber: /^[0-9]{10}$/,
    password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
};

const mongoUrl = process.env.MONGODB_URI;
const dbName = 'myAppDatabase';
let db;

const activeSessions = new Map();

async function verifyPassword(storedHash, inputPassword) {
    try {
        return await argon2.verify(storedHash, inputPassword);
    } catch (err) {
        console.error('Password verification error:', err);
        return false;
    }
}

async function hashPassword(password) {
    try {
        return await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 4
        });
    } catch (err) {
        console.error('Error hashing password:', err);
        throw err;
    }
}

async function logActivity(type, details, success = true) {
    try {
        await db.collection('activityLogs').insertOne({
            type,
            details,
            success,
            timestamp: new Date(),
            environment: process.env.NODE_ENV
        });
    } catch (error) {
        console.error('Logging error:', error);
    }
}

async function logError(error, context) {
    try {
        await db.collection('errorLogs').insertOne({
            error: error.message,
            stack: error.stack,
            context,
            timestamp: new Date(),
            environment: process.env.NODE_ENV
        });
    } catch (err) {
        console.error('Error logging failed:', err);
    }
}

const isSessionValid = (sessionId) => {
    const session = activeSessions.get(sessionId);
    if (!session) return false;
    return Date.now() - session.lastActivity < 30 * 60 * 1000;
};

const checkSession = (req, res, next) => {
    const sessionId = req.session.id;
    if (!isSessionValid(sessionId)) {
        return res.status(401).json({ error: 'Session expired. Please login again.' });
    }
    activeSessions.get(sessionId).lastActivity = Date.now();
    next();
};

async function connectToMongo() {
    try {
        console.log('Attempting to connect to MongoDB Atlas...');
        const client = await MongoClient.connect(mongoUrl, {
            maxPoolSize: 50,
            wtimeoutMS: 2500
        });
        
        console.log('Connected to MongoDB Atlas');
        db = client.db(dbName);


        // Create indexes
        await db.collection('payments').createIndex({ timestamp: -1 });
        await db.collection('payments').createIndex({ customerName: 1 });
        await db.collection('payments').createIndex({ status: 1 });
        await db.collection('users').createIndex({ username: 1 }, { unique: true });
        await db.collection('users').createIndex({ accountNumber: 1 }, { unique: true });
        await db.collection('loginAttempts').createIndex({ "createdAt": 1 }, { expireAfterSeconds: 900 });
        await db.collection('activityLogs').createIndex({ "timestamp": 1 });
        await db.collection('errorLogs').createIndex({ "timestamp": 1 });
        await db.collection('registrationAttempts').createIndex({ "createdAt": 1 }, { expireAfterSeconds: 86400 });
       
        
        // Log existing users
        const users = await db.collection('users').find({}).toArray();
        console.log('Current users in database:', users.map(u => ({
            username: u.username,
            accountNumber: u.accountNumber,
            role: u.role
        })));

        return client;
    } catch (err) {
        console.error('MongoDB connection error:', err);
        await logError(err, 'Database connection');
        throw err;
    }
}

async function recordLoginAttempt(username, successful, req) {
    try {
        const attempt = {
            username,
            successful,
            createdAt: new Date(),
            ip: req.ip,
            userAgent: req.headers['user-agent']
        };

        await db.collection('loginAttempts').insertOne(attempt);
        await logActivity('login_attempt', attempt, successful);

        const failedAttempts = await db.collection('loginAttempts').countDocuments({
            username,
            successful: false,
            createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) }
        });

        return failedAttempts;
    } catch (error) {
        await logError(error, 'Login attempt recording');
        return 0;
    }
}

async function recordRegistrationAttempt(username, successful, req) {
    try {
        const attempt = {
            username,
            successful,
            createdAt: new Date(),
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            type: 'registration'
        };

        await db.collection('registrationAttempts').insertOne(attempt);
        await logActivity('registration_attempt', attempt, successful);
    } catch (error) {
        await logError(error, 'Registration attempt recording');
    }
}

app.post('/api/register-customer', async (req, res) => {
    console.log('Customer registration attempt received');
    console.log('Request body:', req.body);
    
    try {
        const { username, accountNumber, password } = req.body;

        // Input validation
        if (!VALIDATION_PATTERNS.username.test(username)) {
            await logActivity('registration_validation_failed', 
                { username, reason: 'Invalid username format' }, false);
            return res.status(400).json({ 
                error: 'Username must be 4-20 characters and can contain letters, numbers, and underscores.' 
            });
        }
        
        if (!VALIDATION_PATTERNS.accountNumber.test(accountNumber)) {
            await logActivity('registration_validation_failed', 
                { username, reason: 'Invalid account number format' }, false);
            return res.status(400).json({ 
                error: 'Account number must be exactly 10 digits.' 
            });
        }
        
        if (!VALIDATION_PATTERNS.password.test(password)) {
            await logActivity('registration_validation_failed', 
                { username, reason: 'Invalid password format' }, false);
            return res.status(400).json({ 
                error: 'Password must have at least 8 characters, including uppercase, lowercase, numbers, and special characters.' 
            });
        }

        // Check for existing user
        const existingUser = await db.collection('users').findOne({
            $or: [
                { username: username },
                { accountNumber: accountNumber }
            ]
        });

        if (existingUser) {
            await recordRegistrationAttempt(username, false, req);
            return res.status(400).json({ 
                error: 'Username or Account Number already exists' 
            });
        }

        // Hash password
        const hashedPassword = await hashPassword(password);

        // Create new user
        const newUser = {
            username,
            accountNumber,
            password: hashedPassword,
            role: 'customer',
            createdAt: new Date(),
            lastLogin: null,
            failedLoginAttempts: 0,
            status: 'active'
        };

        // Insert user into database
        await db.collection('users').insertOne(newUser);

        // Log successful registration
        await logActivity('customer_registration', {
            username,
            accountNumber,
            timestamp: new Date(),
            role: 'customer'
        }, true);

        await recordRegistrationAttempt(username, true, req);

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please login with your credentials.'
        });

    } catch (error) {
        console.error('Registration error:', error);
        await logError(error, 'Customer registration');
        await recordRegistrationAttempt(req.body.username || 'unknown', false, req);
        
        res.status(500).json({ 
            error: 'Registration failed. Please try again later.' 
        });
    }
});

app.post('/api/login', async (req, res) => {
    console.log('Login attempt received');
    console.log('Request body:', req.body);
    
    try {
        const { username, accountNumber, password } = req.body;

        const user = await db.collection('users').findOne({ username, accountNumber });
        console.log('User found:', user ? 'Yes' : 'No');

        if (!user) {
            await recordLoginAttempt(username, false, req);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await verifyPassword(user.password, password);
        console.log('Password verification result:', validPassword);

        if (!validPassword) {
            const failedAttempts = await recordLoginAttempt(username, false, req);
            return res.status(401).json({ 
                error: 'Invalid credentials',
                attemptsRemaining: 5 - failedAttempts
            });
        }

        const sessionId = crypto.randomBytes(32).toString('hex');
        activeSessions.set(sessionId, {
            userId: user._id,
            lastActivity: Date.now(),
            role: user.role
        });

        await logActivity('successful_login', {
            username: user.username,
            role: user.role,
            timestamp: new Date()
        });

        await recordLoginAttempt(username, true, req);

        res.json({
            success: true,
            user: {
                username: user.username,
                role: user.role,
                accountNumber: user.accountNumber
            },
            sessionId
        });
    } catch (error) {
        console.error('Login error:', error);
        await logError(error, 'Login process');
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

app.get('/api/health', async (req, res) => {
    try {
        await db.command({ ping: 1 });
        res.json({
            status: 'healthy',
            database: 'connected',
            uptime: process.uptime(),
            timestamp: new Date()
        });
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: error.message
        });
    }
});

app.get('/api/check-session', checkSession, (req, res) => {
    res.json({ valid: true });
});

app.post('/api/logout', async (req, res) => {
    const sessionId = req.session.id;
    activeSessions.delete(sessionId);
    req.session.destroy();
    await logActivity('logout', { sessionId });
    res.json({ success: true, message: 'Logged out successfully' });
});


// Payment endpoints
app.post('/api/payments', async (req, res) => {
    try {
        console.log('Payment request received:', req.body);  // Add this line for debugging
        
        const payment = {
            ...req.body,
            createdAt: new Date(),
            status: 'pending'
        };

        // Validate payment data
        if (!payment.amount || payment.amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        // Add payment to database
        const result = await db.collection('payments').insertOne(payment);
        
        await logActivity('payment_created', {
            paymentId: result.insertedId,
            amount: payment.amount,
            customerName: payment.customerName,
            timestamp: payment.timestamp
        });

        console.log('Payment saved successfully:', result.insertedId);  // Add this line for debugging

        res.status(201).json({
            success: true,
            paymentId: result.insertedId
        });
    } catch (error) {
        console.error('Payment creation error:', error);
        await logError(error, 'Payment creation');
        res.status(500).json({ error: 'Failed to process payment' });
    }
});

// Get all payments (for employee dashboard)
app.get('/api/payments', async (req, res) => {
    try {
        const payments = await db.collection('payments')
            .find({})
            .sort({ timestamp: -1 })
            .toArray();

        res.json({ payments });
    } catch (error) {
        console.error('Payment fetch error:', error);
        await logError(error, 'Payment fetch');
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});


const sslOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};

async function startServer() {
    try {
        await connectToMongo();
        const PORT = process.env.PORT || 3001;
        
        https.createServer(sslOptions, app).listen(PORT, () => {
            console.log(`Secure server running on https://localhost:${PORT}`);
        });
    } catch (err) {
        console.error('Failed to start server:', err);
        await logError(err, 'Server startup');
        process.exit(1);
    }
}

startServer();

process.on('SIGINT', async () => {
    if (db) {
        await logActivity('server_shutdown', 'Graceful shutdown initiated');
        await db.client.close();
        console.log('MongoDB connection closed');
    }
    process.exit(0);
});