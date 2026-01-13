# Zero-Defect SaaS Architecture Plan

## 🎯 Architecture Goals
- **Zero-Defect**: Rigorous validation, typing, and error handling.
- **Scalability**: Migration from file-based storage to MongoDB.
- **Real-time**: WebSocket integration for Dashboard.
- **Security**: OAuth2, Webhook verification, Environment variable validation.

## 🛠 Tech Stack
- **Backend**: Node.js, Express, Socket.io
- **Database**: MongoDB (Mongoose Application Layer)
- **Frontend**: React, Vite, TailwindCSS
- **AI**: Ollama (Local), Google Gemini (Cloud fallback)
- **Payments**: Stripe (Link/Card), PayPal (Sandbox/Live)

## 📦 Module Analysis & Action Plan

### 1. Payment System (Foundation)
**Current State**: partial routes in `payment_routes.js`, missing `paypal-rest-sdk`.
**Risks**: Webhook replay attacks, insecure price tampering.
**Action**:
- Install `@paypal/checkout-server-sdk`.
- Implement `PaymentService` with abstract strategy pattern for Stripe/PayPal.
- Create strict Mongoose Schemas: `Transaction`, `Subscription`, `Customer`.
- **Security**: Verify Stripe signatures, validate PayPal IPN/Webhooks.

### 2. Google Integration
**Current State**: `googleapis` installed, `google_service.js` drafted.
**Risks**: Token expiration handling, scope creep.
**Action**:
- Implement `OAuth2` flow properly.
- Store refresh tokens securely in MongoDB (`User` model).
- Create dedicated handlers for Gmail/Calendar/Tasks/Drive.
- **Zero-Defect**: Handle API rate limits and token refresh automatically.

### 3. Project Management (Dart AI)
**Current State**: `dart-tools` wrapper with MOCKED AI breakdown. File-based `project_service.js`.
**Risks**: Data corruption with file sync, poor AI results with mock.
**Action**:
- **Critical**: Migrate `project_service.js` to use MongoDB `Project` and `Task` models.
- **Integrate**: Connect `dart_service.js` to `llm_service.js` to replace the Mock breakdown with real LLM analysis.
- **API**: Ensure specific Dart AI endpoints are fully typed and validated.

### 4. KPI Dashboard
**Current State**: `socket.io` installed but not fully connected to frontend widgets.
**Risks**: Performance bottleneck with polling.
**Action**:
- Implement `SocketService` to broadcast `payment.success`, `task.update`, `system.alert` events.
- Update `ProjectDashboard.jsx` to consume `SocketContext`.

## 📜 Database Schema (MongoDB)

### User
```javascript
{
  email: String,
  googleId: String,
  googleRefreshToken: String,
  tier: { type: String, enum: ['starter', 'pro', 'enterprise'] },
  stripeCustomerId: String,
  roles: [String]
}
```

### Transaction
```javascript
{
  userId: ObjectId,
  amount: Number,
  currency: String,
  provider: { type: String, enum: ['stripe', 'paypal'] },
  status: { type: String, enum: ['pending', 'completed', 'failed'] },
  transactionId: String,
  metadata: Object
}
```

### Project
```javascript
{
  title: String,
  description: String,
  status: String,
  metrics: Object, // KPI data
  tasks: [{ type: ObjectId, ref: 'Task' }]
}
```
