# API Documentation - Nexus33

## Base URL
```
Development: http://localhost:3000
Production: https://api.nexus33.io
```

## Authentication
All endpoints except `/auth/*` require JWT token in header:
```
Authorization: Bearer <token>
```

---

## Auth Routes (`/auth`)

### POST /auth/login
Login with username/password.

**Request:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "success": true,
  "token": "jwt_token",
  "user": { "id": "string", "username": "string", "tier": "string" }
}
```

### POST /auth/register
Register new user.

---

## Security Routes (`/api/security`)

### POST /api/security/quick-scan
Quick security scan for a domain.

**Request:**
```json
{
  "domain": "example.com"
}
```

### GET /api/security/history
Get scan history for current user.

### GET /api/security/scan/:scanId
Get specific scan details.

---

## Payment Routes (`/api/payment`)

### GET /api/payment/pricing
Get pricing information for all tiers.

### POST /api/payment/checkout
Create Stripe checkout session.

**Request:**
```json
{
  "tier": "operator|enterprise|security_starter|security_pro|security_enterprise",
  "billingCycle": "monthly|yearly"
}
```

### POST /api/payment/webhook
Stripe webhook endpoint (internal).

---

## AI Routes

### POST /api/chat
Main chat endpoint.

### GET /api/patterns
Get available Fabric patterns.

### POST /api/experts/query
Query expert agents.

### POST /api/director/chat
Query the Agent Director.

---

## Additional Routes

| Route | Description |
|-------|-------------|
| `/api/subscription` | Subscription management |
| `/api/dart` | Dart AI integration |
| `/api/tracking` | Usage tracking |
| `/api/orchestrator` | Model orchestration |
| `/api/tor` | Tor network tools |
| `/api/shodan` | Shodan OSINT |
| `/api/vpn` | VPN management |
| `/api/network` | Network tools |

---

## Error Responses

All errors follow this format:
```json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE"
}
```

Common codes:
- `UNAUTHORIZED` - Missing or invalid token
- `FORBIDDEN` - Insufficient tier/permissions
- `NOT_FOUND` - Resource not found
- `RATE_LIMIT` - Too many requests
