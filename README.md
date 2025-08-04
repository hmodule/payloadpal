# 🔐 Secure Module Transfer System

A secure, encrypted module distribution system with client-server architecture. This system is designed for transferring highly sensitive modules with proper authentication, encryption, and logging.

## 🏗️ Architecture

- **Server**: Node.js with Express, JWT authentication, AES encryption, and comprehensive logging
- **Client**: C++ with OpenSSL for encryption/decryption and HTTP communication
- **GUI**: Web-based interface accessible from any browser

## 🚀 Features

### Security
- JWT-based authentication with role-based access control
- AES-256-CBC encryption for all module transfers
- Rate limiting and security headers
- Comprehensive audit logging

### Functionality
- Secure module download (one per session)
- Real-time user monitoring (admin only)
- Heartbeat system for connection monitoring
- Session management with automatic cleanup

### User Roles
- **User**: Can download one module per session
- **Admin**: Can view all users, monitor activity, and access system logs

## 📋 Prerequisites

### Server Dependencies
- Node.js (v14 or higher)
- npm

### Client Dependencies
- C++17 compiler (g++ or clang++)
- OpenSSL development libraries
- nlohmann-json (header-only)

## 🛠️ Installation

### 1. Server Setup

```bash
cd server
npm install
```

### 2. Client Setup

```bash
cd ac_client
make install-deps  # Install OpenSSL and dependencies
make all           # Compile the client
```

### 3. Environment Configuration

Create a `.env` file in the server directory (optional):

```env
JWT_SECRET=your-super-secret-jwt-key-change-in-production
ENCRYPTION_KEY=your-32-char-encryption-key-here
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
```

## 🚀 Usage

### Starting the Server

```bash
cd server
npm run dev  # Development mode with auto-restart
# or
npm start    # Production mode
```

The server will start on `http://localhost:1200`

### Using the Web GUI

1. Open your browser and navigate to `http://localhost:1200`
2. Login with credentials:
   - **User**: username: `any_name`, password: `user123`
   - **Admin**: username: `any_name`, password: `admin123`
3. Download modules or view user activity (admin only)

### Using the C++ Client

```bash
cd ac_client
make run
```

Follow the prompts to:
1. Enter username and role
2. Enter password
3. Download modules
4. View user list (admin only)

## 📁 Module Management

### Adding Modules

Place your module files in `server/modules/` with `.txt` extension:

```
server/modules/
├── hello.txt
├── module.txt
└── test.txt
```

### Module Security

- All modules are encrypted with AES-256-CBC before transmission
- Each module download is logged with user details and timestamp
- Only one module can be downloaded per user session

## 🔍 Monitoring & Logging

### Server Logs

Logs are stored in `server/logs/`:
- `combined.log`: All application logs
- `error.log`: Error-level logs only

### Admin Features

Admins can:
- View all active/inactive users
- Monitor module downloads
- Track user IP addresses and session durations
- Access system health information

## 🔐 Security Features

### Authentication
- JWT tokens with 24-hour expiration
- Role-based access control
- Secure password validation

### Encryption
- AES-256-CBC encryption for all module data
- Unique IV (Initialization Vector) for each encryption
- Secure key management

### Network Security
- Rate limiting (100 requests per 15 minutes per IP)
- CORS protection
- Security headers (Helmet.js)
- Input validation and sanitization

## 🧪 Testing

### Test Credentials

**Regular User:**
- Username: `testuser`
- Password: `user123`
- Role: `user`

**Admin User:**
- Username: `admin`
- Password: `admin123`
- Role: `admin`

### Test Modules

Available test modules:
- `hello` - Simple hello world module
- `module` - Sample module content
- `test` - Test module for validation

## 🚨 Security Considerations

### Production Deployment

1. **Change default secrets**: Update JWT_SECRET and ENCRYPTION_KEY
2. **Use HTTPS**: Configure SSL/TLS certificates
3. **Database integration**: Replace in-memory storage with persistent database
4. **Environment variables**: Use proper environment variable management
5. **Firewall configuration**: Restrict access to necessary ports only

### Key Management

- Store encryption keys securely (not in code)
- Rotate keys regularly
- Use hardware security modules (HSM) for production

## 📊 API Endpoints

### Authentication
- `POST /login` - User authentication
- `POST /logout` - User logout

### Module Operations
- `POST /download_module` - Download encrypted module

### Admin Operations
- `GET /get_users` - List all users (admin only)
- `GET /health` - System health check

### System
- `POST /heartbeat` - Client heartbeat
- `GET /health` - Health check

## 🐛 Troubleshooting

### Common Issues

1. **Compilation errors**: Ensure OpenSSL is installed
2. **Connection refused**: Check if server is running on port 1200
3. **Authentication failed**: Verify credentials and server logs
4. **Module not found**: Check if module file exists in `server/modules/`

### Debug Mode

Enable debug logging by setting the log level in `server.js`:

```javascript
const logger = winston.createLogger({
    level: 'debug', // Change from 'info' to 'debug'
    // ... rest of config
});
```

## 📝 License

This project is for educational and demonstration purposes. Use at your own risk in production environments.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review server logs in `server/logs/`
3. Verify all dependencies are installed
4. Ensure proper network connectivity 