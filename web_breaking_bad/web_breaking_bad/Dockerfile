# Production image
FROM node:20-alpine

# Install system packages
RUN apk add --update --no-cache supervisor nginx redis

# Set up application directory
RUN mkdir -p /app
WORKDIR /app

# Copy server dependencies and install them
COPY ./challenge/server/package.json ./server/package.json
WORKDIR /app/server
RUN yarn

# Return to root and install challenge dependencies
WORKDIR /app
COPY ./challenge/package.json ./package.json
RUN yarn

# Copy the entire challenge folder
COPY ./challenge/ .

# Setup configs
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/nginx.conf /etc/nginx/nginx.conf

# Add readflag binary or any other necessary file
COPY flag.txt /

# Expose the port nginx is reachable on
EXPOSE 1337

# Start supervisor
ENTRYPOINT ["supervisord", "-c", "/etc/supervisord.conf"]
