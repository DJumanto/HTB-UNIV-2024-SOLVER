docker rm -f web_intergalatic_bounty
docker build -t web_intergalatic_bounty .
docker run --name=web_intergalatic_bounty --rm -p1337:1337 -p8080:8080 -it web_intergalatic_bounty
