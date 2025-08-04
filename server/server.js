const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const winston = require("winston");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");

const app = express();
const server = http.createServer(app);
const PORT = 1200;
const HEARTBEAT_TIMEOUT = 30 * 1000; // 10 sec
const SELECTION_TIMEOUT = 3 * 60 * 1000; // 3 min
const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production";
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "your-32-char-encryption-key-here";

// Configure Winston logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'module-transfer-server' },
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Create logs directory if it doesn't exist
if (!fs.existsSync('logs')) {
    fs.mkdirSync('logs');
}

// Security middleware with CSP that allows inline scripts
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "http:"],
        },
    },
}));
// app.use(cors({
//     origin: true, // Allow all origins for development
//     credentials: true
// }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Middleware to parse JSON bodies
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

let clients = {}; // Track authenticated users
let admins = new Set(); // Track admin connections
let sessionTokens = new Map(); // Track JWT tokens

// Encryption utilities
function encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', ENCRYPTION_KEY);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted
    };
}

function decryptData(encryptedData, iv) {
    const decipher = crypto.createDecipher('aes-256-cbc', ENCRYPTION_KEY);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        logger.warn('Access attempt without token', { ip: req.ip });
        return res.status(401).json({ error: "Access token required" });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            logger.warn('Invalid token attempt', { ip: req.ip, error: err.message });
            return res.status(403).json({ error: "Invalid token" });
        }
        req.user = user;
        next();
    });
}

// Admin middleware
function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        logger.warn('Unauthorized admin access attempt', { 
            user: req.user?.name, 
            ip: req.ip 
        });
        return res.status(403).json({ error: "Admin access required" });
    }
    next();
}

// Remove inactive users
function checkInactiveUsers() {
    const now = Date.now();
    for (const [userId, client] of Object.entries(clients)) {
        if (client.downloading) continue; // No timeout if downloading
        if (!client.hasSelected && now - client.sessionStart > SELECTION_TIMEOUT) {
            logger.info('Session timeout - user inactive', { 
                userId, 
                name: client.name,
                duration: now - client.sessionStart 
            });
            delete clients[userId];
            sessionTokens.delete(client.token);
            notifyAdmins();
        } else if (now - client.lastHeartbeat > HEARTBEAT_TIMEOUT) {
            logger.info('Heartbeat timeout - user disconnected', { 
                userId, 
                name: client.name,
                lastHeartbeat: client.lastHeartbeat 
            });
            delete clients[userId];
            sessionTokens.delete(client.token);
            notifyAdmins();
        }
    }
}

// Notify admins about active users
function notifyAdmins() {
    const userList = Object.values(clients).map(client => ({
        id: client.userId,
        name: client.name,
        role: client.role,
        module: client.hasDownloaded ? client.module : "None",
        downloading: client.downloading,
        lastHeartbeat: client.lastHeartbeat,
        sessionStart: client.sessionStart,
        ip: client.ip
    }));

    const adminData = JSON.stringify({ 
        type: "admin_update", 
        users: userList,
        timestamp: new Date().toISOString()
    });
    
    admins.forEach(admin => {
        try {
            admin.send(adminData);
        } catch (error) {
            logger.error('Failed to notify admin', { error: error.message });
        }
    });
}

// Check inactive users every 5 sec
setInterval(checkInactiveUsers, 5000);

// Handle login requests
app.post("/login", (req, res) => {
    try {
        const { name, role, password } = req.body.payload;

        if (!name || !password) {
            logger.warn('Login attempt with missing credentials', { ip: req.ip });
            return res.status(400).json({ error: "Name and password required" });
        }

        // In a real system, you'd validate against a database
        // For demo purposes, we'll use a simple check
        const validPassword = role === 'admin' ? 'admin123' : 'user123';
        
        if (password !== validPassword) {
            logger.warn('Failed login attempt', { name, role, ip: req.ip });
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const userId = crypto.randomBytes(16).toString('hex');
        const token = jwt.sign({ 
            userId, 
            name, 
            role, 
            ip: req.ip 
        }, JWT_SECRET, { expiresIn: '24h' });

        clients[userId] = {
            userId,
            name,
            role,
            token,
            ip: req.ip,
            hasDownloaded: false,
            lastHeartbeat: Date.now(),
            sessionStart: Date.now(),
            hasSelected: false,
            downloading: false,
            module: null
        };

        sessionTokens.set(token, userId);

        logger.info('User logged in successfully', { 
            userId, 
            name, 
            role, 
            ip: req.ip 
        });

        notifyAdmins();
        return res.json({ 
            message: "Login successful",
            token,
            role
        });
    } catch (error) {
        logger.error('Login error', { error: error.message, ip: req.ip });
        return res.status(500).json({ error: "Internal server error" });
    }
});

// Handle module download requests
app.post("/download_module", authenticateToken, (req, res) => {
    try {
        const { module_name } = req.body.payload;
        const userId = req.user.userId;
        const client = clients[userId];

        if (!client) {
            logger.warn('Module download attempt by unknown user', { 
                userId, 
                ip: req.ip 
            });
            return res.status(400).json({ error: "User not authenticated" });
        }

        if (client.hasDownloaded) {
            logger.warn('Multiple module download attempt', { 
                userId, 
                name: client.name,
                ip: req.ip 
            });
            return res.status(400).json({ error: "Only one module per session" });
        }

        if (!module_name) {
            return res.status(400).json({ error: "Module name required" });
        }

        const modulePath = path.join(__dirname, "modules", `${module_name}.txt`);
        if (!fs.existsSync(modulePath)) {
            logger.warn('Module not found', { 
                module_name, 
                userId, 
                name: client.name,
                ip: req.ip 
            });
            return res.status(400).json({ error: "Module not found" });
        }

        client.hasDownloaded = true;
        client.downloading = true;
        client.hasSelected = true;
        client.module = module_name;

        logger.info('Module download started', { 
            userId, 
            name: client.name,
            module_name,
            ip: req.ip 
        });

        fs.readFile(modulePath, (err, data) => {
            if (err) {
                logger.error('Failed to read module file', { 
                    module_name, 
                    error: err.message,
                    userId,
                    name: client.name 
                });
                client.downloading = false;
                return res.status(500).json({ error: "Failed to load module" });
            }

            // Encrypt the module data
            const encrypted = encryptData(data.toString());
            
            logger.info('Module downloaded successfully', { 
                userId, 
                name: client.name,
                module_name,
                fileSize: data.length,
                ip: req.ip 
            });

            res.json({ 
                type: "module_data", 
                fileName: `${module_name}`, 
                module_data: encrypted.encryptedData,
                iv: encrypted.iv
            });
            
            client.downloading = false;
            notifyAdmins();
        });
    } catch (error) {
        logger.error('Module download error', { 
            error: error.message, 
            userId: req.user?.userId,
            ip: req.ip 
        });
        return res.status(500).json({ error: "Internal server error" });
    }
});

// Handle heartbeat requests
app.post("/heartbeat", authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const client = clients[userId];

        if (!client) {
            return res.status(400).json({ error: "User not authenticated" });
        }

        client.lastHeartbeat = Date.now();
        notifyAdmins();
        
        logger.debug('Heartbeat received', { 
            userId, 
            name: client.name,
            ip: req.ip 
        });
        
        return res.status(200).json({ message: "Heartbeat received" });
    } catch (error) {
        logger.error('Heartbeat error', { 
            error: error.message, 
            userId: req.user?.userId,
            ip: req.ip 
        });
        return res.status(500).json({ error: "Internal server error" });
    }
});

// Handle logout requests
app.post("/logout", authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const client = clients[userId];

        if (!client) {
            return res.status(400).json({ error: "User not authenticated" });
        }

        logger.info('User logged out', { 
            userId, 
            name: client.name,
            ip: req.ip,
            sessionDuration: Date.now() - client.sessionStart 
        });

        delete clients[userId];
        sessionTokens.delete(client.token);
        notifyAdmins();
        
        return res.json({ message: "Logged out successfully" });
    } catch (error) {
        logger.error('Logout error', { 
            error: error.message, 
            userId: req.user?.userId,
            ip: req.ip 
        });
        return res.status(500).json({ error: "Internal server error" });
    }
});

// Admin endpoint to get all users
app.get("/get_users", authenticateToken, requireAdmin, (req, res) => {
    try {
        const { filter } = req.query; // 'active', 'inactive', or 'all'
        const now = Date.now();
        
        let userList = Object.values(clients).map(client => ({
            id: client.userId,
            name: client.name,
            role: client.role,
            module: client.hasDownloaded ? client.module : "None",
            downloading: client.downloading,
            lastHeartbeat: client.lastHeartbeat,
            sessionStart: client.sessionStart,
            ip: client.ip,
            isActive: now - client.lastHeartbeat <= HEARTBEAT_TIMEOUT
        }));

        // Apply filter if specified
        if (filter === 'active') {
            userList = userList.filter(user => user.isActive);
        } else if (filter === 'inactive') {
            userList = userList.filter(user => !user.isActive);
        }

        logger.info('Admin requested user list', { 
            adminId: req.user.userId,
            adminName: req.user.name,
            filter,
            userCount: userList.length,
            ip: req.ip 
        });

        res.json({ 
            users: userList,
            total: userList.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Get users error', { 
            error: error.message, 
            adminId: req.user?.userId,
            ip: req.ip 
        });
        return res.status(500).json({ error: "Internal server error" });
    }
});

// Health check endpoint
app.get("/health", (req, res) => {
    res.json({ 
        status: "healthy",
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

server.listen(PORT, () => {
    logger.info(`Secure module transfer server running on port ${PORT}`);
    logger.info(`JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
    logger.info(`Encryption Key: ${ENCRYPTION_KEY.substring(0, 10)}...`);
}); 