# Stop and remove containers with the specific name and Dockerfile label

# needs to be fixed, this block doesnt work
$containersToStop = docker ps -q -a  --filter ancestor=fintechtestbed:Dockerfile
foreach ($containerId in $containersToStop) {
    docker stop $containerId
    docker rm $containerId
}

# Causes the script to exit on failure of next commands
$ErrorActionPreference = "Stop"

# Rebuild the Dockerfile
docker build -t "fintechtestbed:Dockerfile" .

# Run the container detached on host port 8000
docker run -d -p 8000:8000 fintechtestbed:Dockerfile > $null

Write-Host "`n`nSuccessfully rebuilt and launched container`n"