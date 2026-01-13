# MongoDB Startup Script for th3-thirty3
# This script starts MongoDB using Docker or local installation

Write-Host "🔍 Checking MongoDB status..." -ForegroundColor Cyan

# Check if Docker is available and running
$dockerRunning = $false
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        $dockerRunning = $true
        Write-Host "✅ Docker is available" -ForegroundColor Green
    }
}
catch {
    Write-Host "⚠️ Docker not available or paused" -ForegroundColor Yellow
}

# Option 1: Use Docker MongoDB
if ($dockerRunning) {
    Write-Host "🐳 Starting MongoDB via Docker..." -ForegroundColor Cyan
    
    # Check if mongodb container exists
    $existingContainer = docker ps -a --filter "name=th3-mongodb" --format "{{.Names}}" 2>&1
    
    if ($existingContainer -eq "th3-mongodb") {
        # Start existing container
        docker start th3-mongodb
        Write-Host "✅ MongoDB container started" -ForegroundColor Green
    }
    else {
        # Create new container
        docker run -d --name th3-mongodb -p 27017:27017 -v mongodb_data:/data/db mongo:latest
        Write-Host "✅ MongoDB container created and started" -ForegroundColor Green
    }
    
    # Wait for MongoDB to be ready
    Write-Host "⏳ Waiting for MongoDB to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    
    # Test connection
    $testResult = docker exec th3-mongodb mongosh --eval "db.adminCommand('ping')" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ MongoDB is ready on localhost:27017" -ForegroundColor Green
    }
    else {
        Write-Host "⚠️ MongoDB may still be starting up..." -ForegroundColor Yellow
    }
}
else {
    Write-Host "⚠️ Docker is not available. Please either:" -ForegroundColor Yellow
    Write-Host "   1. Unpause Docker Desktop" -ForegroundColor White
    Write-Host "   2. Install MongoDB locally" -ForegroundColor White
    Write-Host "" 
    Write-Host "The server will still work with local file fallback for Google tokens." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "To start the server, run: npm run dev" -ForegroundColor Cyan
