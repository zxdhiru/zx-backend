# ZX Authentication Service API Documentation

## 🔑 Authentication Endpoints

### Register a New User
```http
POST /auth/register
Content-Type: application/json

{
    "username": "testuser",
    "email": "test@example.com",
    "password": "Password123!",
    "mobile_number": "+1234567890",
    "name": "Test User"
}
```

**Response (201 Created)**
```json
{
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "name": "Test User",
    "mobile_number": "+1234567890"
}
```

### User Login
```http
POST /auth/login
Content-Type: application/json

{
    "email": "test@example.com",
    "password": "Password123!"
}
```

**Response (200 OK)**
```json
{
    "session_token": "your-session-token",
    "user": {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com",
        "name": "Test User"
    }
}
```

### User Logout
```http
POST /auth/logout
Cookie: session=your-session-token
```

**Response (204 No Content)**

---

## 🔐 OAuth 2.0 Endpoints

### Authorization Request
```http
GET /oauth/authorize
```

**Query Parameters**
- `client_id`: Your OAuth client ID
- `redirect_uri`: Your application's callback URL
- `response_type`: Must be "code"
- `scope`: Space-separated list of requested scopes
- `state`: Random string to prevent CSRF

**Example**
```
GET /oauth/authorize?client_id=your-client-id&redirect_uri=http://localhost:8080/callback&response_type=code&scope=read&state=xyz123
```

### Token Exchange
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=your-authorization-code&
redirect_uri=http://localhost:8080/callback&
client_id=your-client-id&
client_secret=your-client-secret
```

**Response (200 OK)**
```json
{
    "access_token": "your-access-token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "your-refresh-token",
    "scope": "read"
}
```

### Refresh Token
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=your-refresh-token&
client_id=your-client-id&
client_secret=your-client-secret
```

**Response (200 OK)**
```json
{
    "access_token": "new-access-token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "new-refresh-token",
    "scope": "read"
}
```

### Token Revocation
```http
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=token-to-revoke&
client_id=your-client-id&
client_secret=your-client-secret
```

**Response (204 No Content)**

---

## 🛡️ Protected Resource Endpoints

### Get User Profile
```http
GET /api/profile
Authorization: Bearer your-access-token
```

**Response (200 OK)**
```json
{
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "name": "Test User",
    "mobile_number": "+1234567890"
}
```

## ⚠️ Error Responses

All endpoints may return the following error responses:

### 400 Bad Request
```json
{
    "error": "validation_error",
    "message": "Invalid request parameters"
}
```

### 401 Unauthorized
```json
{
    "error": "unauthorized",
    "message": "Invalid credentials"
}
```

### 403 Forbidden
```json
{
    "error": "forbidden",
    "message": "Insufficient permissions"
}
```

### 409 Conflict
```json
{
    "error": "conflict",
    "message": "Resource already exists"
}
```

### 500 Internal Server Error
```json
{
    "error": "internal_error",
    "message": "An unexpected error occurred"
}
```

## 📝 Notes

1. All requests must use HTTPS in production
2. Tokens are valid for:
   - Access Token: 1 hour
   - Refresh Token: 24 hours
   - Authorization Code: 10 minutes
3. Rate limiting may be applied to prevent abuse
4. All timestamps are in UTC
5. Session cookies are HTTP-only and secure 