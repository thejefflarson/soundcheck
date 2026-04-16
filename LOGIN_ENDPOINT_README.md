# Python Login Endpoint with JWT Authentication

A secure, production-ready Flask login endpoint that validates credentials against a database and returns JWT tokens.

## Features

- User registration with password hashing (bcrypt)
- Login endpoint that validates credentials
- JWT access token generation
- JWT refresh token support
- Password strength validation (minimum 8 characters)
- User account activation/deactivation
- Protected endpoints requiring JWT authentication
- SQLAlchemy ORM for database abstraction
- Error handling and validation

## Installation

1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements_login.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and set your JWT_SECRET_KEY
```

## Configuration

### Environment Variables

- `DATABASE_URL`: Database connection string (default: sqlite:///users.db)
- `JWT_SECRET_KEY`: Secret key for signing JWT tokens (CHANGE THIS IN PRODUCTION)
- `FLASK_ENV`: Set to 'production' for production use
- `FLASK_DEBUG`: Set to False in production

### Database Setup

SQLite is used by default for development. For production, use PostgreSQL:

```
DATABASE_URL=postgresql://username:password@localhost:5432/mydb
```

## API Endpoints

### 1. Register User
**POST** `/auth/register`

Request body:
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword123"
}
```

Response (201):
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "is_active": true,
    "created_at": "2024-01-15T10:30:00"
  }
}
```

### 2. Login
**POST** `/auth/login`

Request body:
```json
{
  "username": "john_doe",
  "password": "securepassword123"
}
```

Response (200):
```json
{
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "is_active": true,
    "created_at": "2024-01-15T10:30:00"
  }
}
```

### 3. Get User Profile (Protected)
**GET** `/api/me`

Headers:
```
Authorization: Bearer <access_token>
```

Response (200):
```json
{
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "is_active": true,
    "created_at": "2024-01-15T10:30:00"
  }
}
```

### 4. Logout
**POST** `/auth/logout`

Response (200):
```json
{
  "message": "Logged out successfully"
}
```

## Running the Application

```bash
python login_endpoint.py
```

The server will start on `http://localhost:5000`

## Testing the Endpoints

### Using curl:

Register:
```bash
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

Login:
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "securepassword123"
  }'
```

Get Profile (replace TOKEN with actual access_token):
```bash
curl -X GET http://localhost:5000/api/me \
  -H "Authorization: Bearer TOKEN"
```

### Using Python:
See `example_client.py` for a complete example.

## Security Considerations

### Implemented:
✅ Password hashing using Werkzeug (bcrypt)
✅ JWT token expiration (1 hour for access, 30 days for refresh)
✅ Password length validation (minimum 8 characters)
✅ Credential masking (don't reveal if username or password is wrong)
✅ HTTPS enforcement recommended for production
✅ SQLAlchemy for SQL injection prevention

### Production Recommendations:
1. **Change JWT_SECRET_KEY** to a strong, random value
2. **Use HTTPS** in production
3. **Set FLASK_DEBUG = False** in production
4. **Use PostgreSQL** instead of SQLite
5. **Implement rate limiting** to prevent brute force attacks:
```python
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)
@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    ...
```

6. **Add token blacklisting** for logout functionality:
```python
from flask_jwt import decode_token
blacklist = set()

@app.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"message": "Logged out"}), 200

@jwt.token_in_blacklist_loader
def check_if_token_revoked(jwt_payload):
    return jwt_payload['jti'] in blacklist
```

7. **Add email verification** for registration
8. **Add CORS** if needed:
```python
from flask_cors import CORS
CORS(app, resources={r"/auth/*": {"origins": "https://yourdomain.com"}})
```

9. **Log authentication attempts** for security monitoring
10. **Use environment variables** for all sensitive configuration

## Error Responses

| Status | Error | Meaning |
|--------|-------|---------|
| 400 | Missing required fields | Incomplete request |
| 401 | Invalid credentials | Wrong username or password |
| 403 | User account is disabled | User is deactivated |
| 404 | User not found | User doesn't exist |
| 409 | Username/Email already exists | Duplicate user |
| 500 | Internal server error | Server error |

## Extending the Endpoint

### Add Password Reset:
```python
@app.route('/auth/forgot-password', methods=['POST'])
def forgot_password():
    email = request.json.get('email')
    # Send reset email with token
    
@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    token = request.json.get('token')
    new_password = request.json.get('password')
    # Validate token and update password
```

### Add Email Verification:
```python
class User(db.Model):
    email_verified = db.Column(db.Boolean, default=False)
    
@app.route('/auth/verify-email/<token>', methods=['GET'])
def verify_email(token):
    # Verify token and mark email as verified
```

### Add Role-Based Access Control:
```python
class User(db.Model):
    role = db.Column(db.String(20), default='user')  # user, admin, etc.
    
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper
```

## License

MIT License - Feel free to use in your projects
