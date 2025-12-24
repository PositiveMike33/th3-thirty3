# HackerAI Docker Launcher for Windows
# This script starts HackerAI in Docker mode by running it through WSL

param(
    [string]$Token = "hsb_6fcf5517544310ed4213f5e6a4eea82e64efb99abcbb2e4b7f81cc0f29a4ed82",
    [string]$Name = "Th3Thirty3-Docker",
    [string]$Image = ""
)

Write-Host "🚀 Starting HackerAI Docker Sandbox..." -ForegroundColor Cyan

# Check if Docker is running
$dockerProcess = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue
if (-not $dockerProcess) {
    Write-Host "❌ Docker Desktop is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Build the image argument if specified
$imageArg = ""
if ($Image) {
    $imageArg = " --image $Image"
}

# Try to run directly
Write-Host "📦 Pulling HackerAI sandbox image..." -ForegroundColor Yellow
docker pull hackerai/sandbox:latest

# Create container manually if package fails
$containerName = "hackerai-$Name"
$existingContainer = docker ps -a --filter "name=$containerName" --format "{{.Names}}"

if ($existingContainer) {
    Write-Host "🔄 Removing existing container..." -ForegroundColor Yellow
    docker rm -f $containerName | Out-Null
}

Write-Host "🐳 Creating HackerAI container..." -ForegroundColor Green

# Create container with pentesting capabilities
$image = if ($Image) { $Image } else { "hackerai/sandbox:latest" }
docker run -d `
    --name $containerName `
    --cap-add=NET_RAW `
    --cap-add=NET_ADMIN `
    --cap-add=SYS_PTRACE `
    --network host `
    $image `
    tail -f /dev/null

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Container created: $containerName" -ForegroundColor Green
    Write-Host ""
    Write-Host "📝 Now launching HackerAI client..." -ForegroundColor Cyan
    
    # Now run the hackerai client in dangerous mode but it will actually use the container
    # The container is ready, we just need to connect to HackerAI
    hackerai-local --token $Token --name $Name --dangerous
} else {
    Write-Host "❌ Failed to create container" -ForegroundColor Red
    exit 1
}
