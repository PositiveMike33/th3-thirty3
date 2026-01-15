# Stop and remove existing container if it exists
docker stop nexus-mongo 2>$null
docker rm nexus-mongo 2>$null

# Pull latest MongoDB image
Write-Host "Pulling MongoDB Image..."
docker pull mongo:latest

# Run new container
Write-Host "Starting MongoDB Container (nexus-mongo)..."
docker run -d --name nexus-mongo --restart always -p 27017:27017 mongo:latest

# Wait for startup
Write-Host "Waiting for MongoDB to initialize..."
Start-Sleep -Seconds 5

# Check status
$status = docker inspect -f '{{.State.Status}}' nexus-mongo
Write-Host "MongoDB Status: $status"

if ($status -eq "running") {
    Write-Host "MongoDB is ready at mongodb://localhost:27017"
}
else {
    Write-Host "MongoDB failed to start."
    exit 1
}
