# 🔐 Tor Secure Configuration Guide
## Th3 Thirty3 - Secure Anonymous Network Access

This guide documents the secure Tor configuration with authentication for the Th3 Thirty3 project.

## ✅ What Has Been Configured

### 1. **Secure `torrc` Configuration** (`C:\Tor\torrc`)

The following security and performance features have been implemented:

- **✅ SOCKS Proxy** on port `9050` - For anonymous browsing
- **✅ Control Port** on port `9051` - For programmatic circuit changes
- **✅ Hashed Password Authentication** - Prevents unauthorized access to Control Port
- **✅ Cookie Authentication** - Additional security layer
- **✅ GeoIP File Paths** - Properly configured for country-based routing
- **✅ DNS Resolution** through Tor on port `9053`
- **✅ SafeLogging** - Prevents sensitive data in logs
- **✅ Client-Only Mode** - Optimized for client operations

### 2. **Environment Variables** (`.env`)

Add these to your `.env` file (see `.env.tor.example`):

```bash
TOR_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_CONTROL_PASSWORD=Th3Thirty3SecureTor2024!
TOR_EXE_PATH=C:\Tor\tor\tor.exe
TORRC_PATH=C:\Tor\torrc
```

### 3. **Updated Services**

- **`tor_network_service.js`** - Now uses authenticated Control Port
- **`tor_startup_check.js`** - Already configured for multi-method verification

## 🔒 Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| Control Port Authentication | ✅ **ENABLED** | Password-protected Control Port prevents unauthorized circuit changes |
| Cookie Authentication | ✅ **ENABLED** | Additional authentication layer |
| GeoIP Files | ✅ **CONFIGURED** | Proper paths for country-based routing |
| Safe Logging | ✅ **ENABLED** | Sensitive information not logged |
| Circuit Timeout | ✅ **OPTIMIZED** | Faster circuit building |
| DNS Through Tor | ✅ **ENABLED** | DNS queries go through Tor network |

## 🧪 Testing

### Run Comprehensive Test

```bash
node server/tests/test_tor_secure_connection.js
```

This test verifies:

1. ✅ SOCKS Port connectivity (9050)
2. ✅ Control Port connectivity (9051)
3. ✅ Password authentication
4. ✅ Circuit change capability (NEWNYM)
5. ✅ Tor network verification (check.torproject.org)
6. ✅ Circuit information retrieval

**Expected Result:** `6/6 tests passed (100%)`

### Quick Status Check

```bash
# From project directory
node -e "require('./server/tor_startup_check').performStartupCheck()"
```

## 🚀 Usage in Code

### Basic Tor Request

```javascript
const TorNetworkService = require('./server/tor_network_service');
const torService = new TorNetworkService();

// Make anonymous request
const response = await torService.torFetch('https://check.torproject.org/api/ip');
const data = await response.json();
console.log('Exit IP:', data.IP);
```

### Change Circuit (New IP)

```javascript
// Change to new exit node/IP
const result = await torService.changeCircuit();
console.log(result.message); // "Nouveau circuit Tor établi"

// Verify new IP
const newIP = await torService.getCurrentIP();
console.log('New exit IP:', newIP);
```

### Secure Dark Web Access

```javascript
// Access .onion site with automatic trace clearing
const result = await torService.secureDarkWebRequest('http://example.onion');
console.log('Pre-request IP:', result.preRequestIP);
console.log('Post-request IP:', result.postRequestIP);
console.log('Traces cleared:', result.tracesCleared);
```

### Auto IP Rotation

```javascript
// Rotate IP every 5 minutes
torService.startAutoRotation(300000);

// Stop rotation
torService.stopAutoRotation();
```

## 🛠 Maintenance

### Restart Tor with New Config

```powershell
taskkill /F /IM tor.exe
Start-Process -FilePath "C:\Tor\tor\tor.exe" -ArgumentList "-f", "C:\Tor\torrc" -WindowStyle Hidden
```

### View Tor Logs

```powershell
Get-Content "C:\Tor\tor.log" -Tail 50 -Wait
```

### Check Tor Process

```powershell
Get-Process -Name "tor" | Select-Object Id, ProcessName, StartTime
```

### Test SOCKS Port

```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 9050
```

### Test Control Port

```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 9051
```

## 🔐 Changing the Password

### 1. Generate New Hashed Password

```powershell
cd C:\Tor\tor
.\tor.exe --hash-password "YourNewPassword"
```

Copy the output starting with `16:...`

### 2. Update `torrc`

Replace the `HashedControlPassword` line:

```
HashedControlPassword 16:YOUR_NEW_HASH_HERE
```

### 3. Update `.env`

```
TOR_CONTROL_PASSWORD=YourNewPassword
```

### 4. Restart Tor

```powershell
taskkill /F /IM tor.exe
Start-Process -FilePath "C:\Tor\tor\tor.exe" -ArgumentList "-f", "C:\Tor\torrc" -WindowStyle Hidden
```

## 📊 API Endpoints

The following API endpoints use Tor:

- `/api/tor/status` - Get Tor connection status
- `/api/tor/change-circuit` - Change to new IP
- `/api/tor/verify` - Verify Tor connection
- `/api/darkweb/*` - Dark web operations (if implemented)

## ⚠️ Important Security Notes

1. **Never commit `.env` file** - It contains the plaintext password
2. **Keep `torrc` secure** - Only admins should have write access
3. **Monitor Tor logs** - Check for authentication failures
4. **Use HTTPS when possible** - Tor doesn't encrypt endpoint connections
5. **Clear traces after sensitive operations** - Use `clearTraces()` method

## 🎯 Troubleshooting

### Authentication Failed

**Problem:** `515 Authentication failed` error

**Solution:**
1. Verify password in `.env` matches the one used to generate hash
2. Regenerate hash and update `torrc`
3. Restart Tor

### Port Already in Use

**Problem:** Tor won't start, port 9050 busy

**Solution:**
```powershell
# Kill all tor processes
taskkill /F /IM tor.exe

# Find process using port
netstat -ano | findstr :9050

# Kill specific PID
taskkill /F /PID <PID>
```

### Circuit Change Too Frequent

**Problem:** `NEWNYM` rate limiting

**Solution:**
- Wait at least 10 seconds between circuit changes
- Tor enforces rate limits to prevent abuse

### GeoIP Warnings

**Problem:** Warnings about GeoIP files

**Solution:**
- Files should be at `C:\Tor\Data\geoip` and `C:\Tor\Data\geoip6`
- Check paths in `torrc` match actual file locations

## 📝 Next Steps

1. **Add environment variables** to your `.env` file
2. **Test the configuration** with the test script
3. **Integrate Tor** into your application services
4. **Monitor performance** and adjust circuit timeout if needed
5. **Document** any custom Tor integration in your code

---

**Congratulations!** You now have a secure, authenticated Tor setup ready for anonymous OSINT and cybersecurity operations. 🎉
