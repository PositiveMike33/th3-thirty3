$baseUrl = "http://localhost:3000"

# 1. Register User (mapadmin to be upgraded)
$registerBody = @{
    username  = "mapadmin"
    email     = "mapadmin@test.com"
    password  = "password123"
    firstName = "Map"
    lastName  = "Admin"
} | ConvertTo-Json

Write-Host "Registering User..."
try {
    $regResponse = Invoke-RestMethod -Uri "$baseUrl/auth/register" -Method Post -Body $registerBody -ContentType "application/json" -ErrorAction Stop
    $token = $regResponse.token
    Write-Host "Registration Successful. Token obtained."
}
catch {
    Write-Host "Registration failed. Trying Login..."
    $loginBody = @{
        email    = "mapadmin@test.com"
        password = "password123"
    } | ConvertTo-Json
    
    try {
        $loginResponse = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -ErrorAction Stop
        $token = $loginResponse.token
        Write-Host "Login Successful. Token obtained."
    }
    catch {
        Write-Error "Login failed: $_"
        exit 1
    }
}

# 2. Test Chat for Map Analysis
$chatBody = @{
    message  = "Analyze the map and calculate a route from New York to Boston."
    provider = "anythingllm"
} | ConvertTo-Json

$headers = @{
    Authorization = "Bearer $token"
}

Write-Host "Sending Chat Request..."
try {
    $chatResponse = Invoke-RestMethod -Uri "$baseUrl/chat" -Method Post -Body $chatBody -Headers $headers -ContentType "application/json"
    Write-Host "Chat Response Received."
    
    $reply = $chatResponse.reply
    Write-Host "Reply Content:"
    Write-Host $reply
    
    # Check for JSON protocol in response
    # looking for ```json or just json object pattern
    if ($reply -like "*json*") {
        Write-Host "SUCCESS: JSON tag detected in response!"
        if ($reply -like "*action*route*") {
            Write-Host "SUCCESS: Route action detected!"
        }
        else {
            Write-Warning "JSON detected but 'route' action not explicitly found in snippet (might be valid though)."
        }
    }
    else {
        Write-Warning "JSON Protocol NOT detected. The model might have ignored the system prompt."
    }
}
catch {
    Write-Error "Chat request failed: $_"
    exit 1
}
