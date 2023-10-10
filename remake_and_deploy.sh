# Kills the container with name personal_website:Dockerfile
docker rm $(docker stop $(docker ps -q -a  --filter ancestor=fintechtestbed:Dockerfile) 2> /dev/null) 2> /dev/null

# Causes script to exit on failure of next commands
set -e

# Rebuilds the dockerfile
docker build -t "fintechtestbed:Dockerfile" .

# Runs the container detached on host port80
docker run -d -p 8000:8000 fintechtestbed:Dockerfile > /dev/null

echo -e "\n\nSuccessfully rebuilt and launched container\n"