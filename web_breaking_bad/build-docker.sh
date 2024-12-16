#!/bin/bash
docker rm -f web_breaking_bank
docker build -t web_breaking_bank .
docker run --rm -it -p 1337:1337 --name=web_breaking_bank web_breaking_bank